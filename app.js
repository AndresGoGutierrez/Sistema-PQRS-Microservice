require("dotenv").config()
const express = require("express")
const mysql = require("mysql")
const cors = require("cors")
const jwt = require("jsonwebtoken")
const axios = require("axios")
const config = require("./config")

const app = express()

// Database connection
const db = mysql.createConnection(config.database)

db.connect((err) => {
  if (err) {
    console.error("Error connecting to the database:", err.stack)
    return
  }
  console.log("Connected to PQRS database")
})

// Middleware
app.use(
  cors({
    origin: ["http://localhost:3000", "http://localhost:5173"], // Frontend URLs
    credentials: true,
  }),
)
app.use(express.json())

// JWT verification middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1] || req.headers["x-access-token"]

  if (!token) {
    return res.status(401).json({ message: "No token provided" })
  }

  try {
    console.log("Verifying token:", token)
    const decoded = jwt.verify(token, config.jwtSecret)
    console.log("Decoded token:", decoded)

    // Normalizar la estructura del usuario
    req.user = {
      id: decoded.id || decoded.user_id || decoded.userId,
      username: decoded.username || decoded.name,
      email: decoded.email,
      roles: decoded.roles || [],
    }

    // Asegurar que roles sea un array
    if (typeof req.user.roles === "string") {
      req.user.roles = [req.user.roles]
    }

    // Si no hay roles, asignar rol de usuario por defecto
    if (!req.user.roles || !Array.isArray(req.user.roles) || req.user.roles.length === 0) {
      req.user.roles = ["user"]
    }

    console.log("Normalized user:", req.user)
    next()
  } catch (error) {
    console.error("Token verification error:", error)
    return res.status(401).json({ message: "Invalid token" })
  }
}

// Middleware para obtener roles del usuario desde el microservicio de autenticación
const getUserRoles = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1] || req.headers["x-access-token"]

    if (!token) {
      return next()
    }

    console.log("Fetching user roles from auth service...")

    try {
      const response = await axios.post(
        "http://localhost:4000/api/auth/verify",
        { token },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "x-access-token": token,
            "Content-Type": "application/json",
          },
        },
      )

      console.log("Auth service response:", response.data)

      if (response.data && response.data.roles) {
        // Extraer los nombres de los roles
        const roleNames = response.data.roles.map((role) => role.name || role)
        req.user.roles = roleNames
        console.log("Updated user roles from auth service:", roleNames)
      }
    } catch (authError) {
      console.log("Could not fetch roles from auth service:", authError.message)
      // Continuar con los roles por defecto
    }

    next()
  } catch (error) {
    console.error("Error in getUserRoles middleware:", error)
    next()
  }
}

// Role verification middleware
const requireRole = (roles) => {
  return (req, res, next) => {
    console.log("Checking roles. Required:", roles, "User has:", req.user.roles)

    if (!req.user) {
      return res.status(403).json({ message: "User not found" })
    }

    if (!req.user.roles || !Array.isArray(req.user.roles)) {
      return res.status(403).json({ message: "No roles found" })
    }

    const hasRole = roles.some((role) => req.user.roles.includes(role))
    if (!hasRole) {
      return res.status(403).json({
        message: "Insufficient permissions",
        required: roles,
        current: req.user.roles,
      })
    }

    console.log("Role check passed!")
    next()
  }
}

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "OK", service: "PQRS Microservice" })
})

// Debug endpoint to check token
app.get("/api/debug/token", verifyToken, getUserRoles, (req, res) => {
  res.json({
    user: req.user,
    message: "Token is valid",
  })
})

// IMPORTANT: Statistics route MUST come before the dynamic :id route
app.get("/api/pqrs/stats", verifyToken, getUserRoles, requireRole(["admin", "moderator"]), (req, res) => {
  console.log("Stats endpoint hit by user:", req.user)

  const queries = [
    "SELECT COUNT(*) as total FROM pqrssi",
    "SELECT COUNT(*) as pending FROM pqrssi WHERE estado_id = 1",
    "SELECT COUNT(*) as in_progress FROM pqrssi WHERE estado_id = 2",
    "SELECT COUNT(*) as completed FROM pqrssi WHERE estado_id = 3",
  ]

  Promise.all(
    queries.map((query) => {
      return new Promise((resolve, reject) => {
        db.query(query, (err, results) => {
          if (err) reject(err)
          else resolve(results[0])
        })
      })
    }),
  )
    .then((results) => {
      const stats = {
        total: results[0].total,
        pending: results[1].pending,
        inProgress: results[2].in_progress,
        completed: results[3].completed,
      }
      console.log("Returning stats:", stats)
      res.json(stats)
    })
    .catch((err) => {
      console.error("Error fetching statistics:", err)
      res.status(500).json({ message: "Error fetching statistics", error: err })
    })
})

// Routes

// Get all categories
app.get("/api/categories", verifyToken, getUserRoles, (req, res) => {
  db.query("SELECT * FROM categorias", (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching categories", error: err })
    }
    res.json(results)
  })
})

// Get all states
app.get("/api/states", verifyToken, getUserRoles, (req, res) => {
  db.query("SELECT * FROM estados", (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching states", error: err })
    }
    res.json(results)
  })
})

// Create a new PQRS
app.post("/api/pqrs", verifyToken, getUserRoles, (req, res) => {
  const { tipo, descripcion, categoria_id } = req.body
  const mongoUserId = req.user.id // MongoDB ID from JWT
  const estado_id = 1 // Initial state: Pending

  if (!tipo || !descripcion || !categoria_id) {
    return res.status(400).json({ message: "Missing required fields" })
  }

  // First, check if we have a mapping for this MongoDB user ID
  db.query("SELECT id FROM usuarios WHERE mongo_id = ?", [mongoUserId], (err, results) => {
    if (err) {
      console.error("Error checking user mapping:", err)
      return res.status(500).json({ message: "Error checking user mapping", error: err })
    }

    let mysqlUserId

    if (results.length > 0) {
      // We have a mapping, use the existing MySQL user ID
      mysqlUserId = results[0].id
      console.log(`Found existing user mapping: MongoDB ID ${mongoUserId} -> MySQL ID ${mysqlUserId}`)
      insertPQRS(mysqlUserId)
    } else {
      // No mapping exists, create a new user in the MySQL database
      console.log(`No mapping found for MongoDB user ID ${mongoUserId}, creating new user`)

      // Create a placeholder user with the MongoDB ID as reference
      db.query(
        "INSERT INTO usuarios (nombre, email, contraseña, mongo_id) VALUES (?, ?, ?, ?)",
        [
          `User-${mongoUserId.substring(0, 8)}`,
          `user-${mongoUserId.substring(0, 8)}@example.com`,
          "placeholder",
          mongoUserId,
        ],
        (err, result) => {
          if (err) {
            console.error("Error creating user mapping:", err)
            return res.status(500).json({ message: "Error creating user mapping", error: err })
          }

          mysqlUserId = result.insertId
          console.log(`Created new user mapping: MongoDB ID ${mongoUserId} -> MySQL ID ${mysqlUserId}`)
          insertPQRS(mysqlUserId)
        },
      )
    }

    function insertPQRS(userId) {
      db.query(
        "INSERT INTO pqrssi (tipo, descripcion, usuario_id, estado_id, categoria_id) VALUES (?, ?, ?, ?, ?)",
        [tipo, descripcion, userId, estado_id, categoria_id],
        (err, result) => {
          if (err) {
            console.error("Error creating PQRS:", err)
            return res.status(500).json({ message: "Error creating PQRS", error: err })
          }

          const pqrssi_id = result.insertId

          // Add to history
          db.query(
            "INSERT INTO historial (pqrssi_id, estado_id, comentario) VALUES (?, ?, ?)",
            [pqrssi_id, estado_id, "PQRS created"],
            (err) => {
              if (err) {
                console.error("Error adding to history:", err)
              }
            },
          )

          res.status(201).json({
            message: "PQRS created successfully",
            id: pqrssi_id,
          })
        },
      )
    }
  })
})

// Get PQRS (users see only their own, admins/moderators see all)
app.get("/api/pqrs", verifyToken, getUserRoles, (req, res) => {
  const isAdminOrModerator =
    req.user.roles &&
    Array.isArray(req.user.roles) &&
    (req.user.roles.includes("admin") || req.user.roles.includes("moderator"))

  console.log("Getting PQRS for user:", req.user.id, "Is admin/moderator:", isAdminOrModerator)

  const mongoUserId = req.user.id // MongoDB ID from JWT

  // First, get the MySQL user ID from the MongoDB ID
  db.query("SELECT id FROM usuarios WHERE mongo_id = ?", [mongoUserId], (err, userResults) => {
    if (err) {
      console.error("Error finding user mapping:", err)
      return res.status(500).json({ message: "Error finding user mapping", error: err })
    }

    if (userResults.length === 0 && !isAdminOrModerator) {
      // No mapping exists and user is not admin/moderator, return empty array
      return res.json([])
    }

    const mysqlUserId = userResults.length > 0 ? userResults[0].id : null

    let query = `
      SELECT p.id, p.tipo, p.descripcion, e.nombre AS estado, p.fecha, 
             c.nombre AS categoria, p.usuario_id
      FROM pqrssi p
      JOIN estados e ON p.estado_id = e.id
      JOIN categorias c ON p.categoria_id = c.id
    `

    const params = []

    if (!isAdminOrModerator && mysqlUserId) {
      query += " WHERE p.usuario_id = ?"
      params.push(mysqlUserId)
    }

    query += " ORDER BY p.fecha DESC"

    db.query(query, params, (err, results) => {
      if (err) {
        console.error("Error fetching PQRS:", err)
        return res.status(500).json({ message: "Error fetching PQRS", error: err })
      }
      console.log(`Found ${results.length} PQRS records`)
      res.json(results)
    })
  })
})

// Get specific PQRS by ID (MUST come after /stats route)
app.get("/api/pqrs/:id", verifyToken, getUserRoles, (req, res) => {
  const pqrsId = req.params.id
  const mongoUserId = req.user.id // MongoDB ID from JWT
  const isAdminOrModerator =
    req.user.roles &&
    Array.isArray(req.user.roles) &&
    (req.user.roles.includes("admin") || req.user.roles.includes("moderator"))

  console.log("Getting PQRS ID:", pqrsId, "for user:", mongoUserId)

  // First, get the MySQL user ID from the MongoDB ID
  db.query("SELECT id FROM usuarios WHERE mongo_id = ?", [mongoUserId], (err, userResults) => {
    if (err) {
      console.error("Error finding user mapping:", err)
      return res.status(500).json({ message: "Error finding user mapping", error: err })
    }

    const mysqlUserId = userResults.length > 0 ? userResults[0].id : null

    let query = `
      SELECT p.id, p.tipo, p.descripcion, e.nombre AS estado, p.fecha, 
             c.nombre AS categoria, p.usuario_id, p.estado_id
      FROM pqrssi p
      JOIN estados e ON p.estado_id = e.id
      JOIN categorias c ON p.categoria_id = c.id
      WHERE p.id = ?
    `

    const params = [pqrsId]

    if (!isAdminOrModerator && mysqlUserId) {
      query += " AND p.usuario_id = ?"
      params.push(mysqlUserId)
    }

    db.query(query, params, (err, results) => {
      if (err) {
        console.error("Error fetching PQRS:", err)
        return res.status(500).json({ message: "Error fetching PQRS", error: err })
      }

      if (results.length === 0) {
        return res.status(404).json({ message: "PQRS not found or access denied" })
      }

      res.json(results[0])
    })
  })
})

// Update PQRS status (only admin and moderator)
app.put("/api/pqrs/:id/status", verifyToken, getUserRoles, requireRole(["admin", "moderator"]), (req, res) => {
  const pqrsId = req.params.id
  const { estado_id, comentario } = req.body

  if (!estado_id) {
    return res.status(400).json({ message: "Estado ID is required" })
  }

  db.query("UPDATE pqrssi SET estado_id = ? WHERE id = ?", [estado_id, pqrsId], (err) => {
    if (err) {
      console.error("Error updating PQRS status:", err)
      return res.status(500).json({ message: "Error updating PQRS status", error: err })
    }

    // Add to history
    const comentarioCompleto = `Status changed by ${req.user.roles.includes("admin") ? "admin" : "moderator"}: ${comentario || "No comment"}`

    db.query(
      "INSERT INTO historial (pqrssi_id, estado_id, comentario) VALUES (?, ?, ?)",
      [pqrsId, estado_id, comentarioCompleto],
      (err) => {
        if (err) {
          console.error("Error adding to history:", err)
        }
      },
    )

    res.json({ message: "PQRS status updated successfully" })
  })
})

// Get PQRS history
app.get("/api/pqrs/:id/history", verifyToken, getUserRoles, (req, res) => {
  const pqrsId = req.params.id
  const mongoUserId = req.user.id // MongoDB ID from JWT
  const isAdminOrModerator =
    req.user.roles &&
    Array.isArray(req.user.roles) &&
    (req.user.roles.includes("admin") || req.user.roles.includes("moderator"))

  // First, get the MySQL user ID from the MongoDB ID
  db.query("SELECT id FROM usuarios WHERE mongo_id = ?", [mongoUserId], (err, userResults) => {
    if (err) {
      console.error("Error finding user mapping:", err)
      return res.status(500).json({ message: "Error finding user mapping", error: err })
    }

    const mysqlUserId = userResults.length > 0 ? userResults[0].id : null

    // First check if user has access to this PQRS
    const accessQuery = "SELECT usuario_id FROM pqrssi WHERE id = ?"
    const accessParams = [pqrsId]

    db.query(accessQuery, accessParams, (err, pqrsResults) => {
      if (err) {
        console.error("Error checking PQRS access:", err)
        return res.status(500).json({ message: "Error checking PQRS access", error: err })
      }

      if (pqrsResults.length === 0) {
        return res.status(404).json({ message: "PQRS not found" })
      }

      // Check if user has access
      if (!isAdminOrModerator && mysqlUserId && pqrsResults[0].usuario_id !== mysqlUserId) {
        return res.status(403).json({ message: "Access denied" })
      }

      // Get history
      db.query(
        `
          SELECT h.id, h.fecha, e.nombre AS estado, h.comentario
          FROM historial h
          JOIN estados e ON h.estado_id = e.id
          WHERE h.pqrssi_id = ?
          ORDER BY h.fecha DESC
        `,
        [pqrsId],
        (err, results) => {
          if (err) {
            console.error("Error fetching PQRS history:", err)
            return res.status(500).json({ message: "Error fetching PQRS history", error: err })
          }
          res.json(results)
        },
      )
    })
  })
})

const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
  console.log(`PQRS Microservice running on port ${PORT}`)
})
