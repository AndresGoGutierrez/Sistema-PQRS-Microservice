const express = require('express'); // Import the express module
const mysql = require('mysql'); // Import the mysql module
const path = require('path'); // Import the path module
const bodyParser = require('body-parser'); // Import the body-parser module
const session = require('express-session'); // Import the express-session module
const bcrypt = require('bcrypt'); // Import the bcrypt module for password hashing
const config = require('./config'); // Import the config.js file for database credentials

const app = express(); // Create an instance of express

const db = mysql.createConnection(config); // Create a database connection using the config.js settings

db.connect(err => { // Connect to the database
    if (err) {
        console.error('Error connecting to the database:', err.stack);
        return;
    }
    console.log('Connected to the database'); // Confirmation message for successful connection
});

app.set('view engine', 'ejs'); // Set the template engine to EJS
app.set('views', path.join(__dirname, 'views')); // Set the views directory path

app.use(bodyParser.urlencoded({ extended: false })); // Configure body-parser to parse URL-encoded data
app.use(express.static(path.join(__dirname, 'public'))); // Set the static files folder

app.use(session({ // Configure sessions
    secret: 'your_secret_key', // Secret key to sign the session
    resave: false, // Do not save session if unmodified
    saveUninitialized: true // Save new but uninitialized sessions
}));

// Main route
app.get('/', (req, res) => {
    res.render('index', { nombre: req.session.nombre, isAdmin: req.session.isAdmin }); // Render index view and pass session username
});

// Register route
app.get('/register', (req, res) => {
    res.render('register'); // Render the register view
});

app.post('/register', async (req, res) => {
    const { nombre, email, contraseña } = req.body; // Get form data
    const hashedPassword = await bcrypt.hash(contraseña, 10); // Hash the password

    var contraseñaRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()+,.?":{}|<>]).{8,}$/;

    if (!contraseñaRegex.test(contraseña)) {
        return res.send("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.")
    } else {
        db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, results) => {
            if (err) throw err;
            if (results.length > 0) {
                return res.send('Email is already registered'); // If email exists, send a message
            } else {
                db.query('INSERT INTO usuarios (nombre, email, contraseña) VALUES (?, ?, ?)',
                    [nombre, email, hashedPassword],
                    (err, result) => {
                        if (err) throw err;
                        res.redirect('/login'); // Redirect to login page
                    });
            }
        });
    }
});

// Login route
app.get('/login', (req, res) => {
    res.render('login'); // Render the login view
});

app.post('/login', (req, res) => {
    const { email, contraseña } = req.body; // Get form data
    db.query('SELECT * FROM usuarios WHERE email = ?', [email], async (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            const user = results[0];
            if (await bcrypt.compare(contraseña, user.contraseña)) { // Compare hashed password
                req.session.loggedin = true; // Mark session as logged in
                req.session.nombre = user.nombre; // Save username in session
                req.session.userId = user.id; // Save user ID in session
                req.session.isAdmin = user.is_admin; // Save admin status in session
                res.redirect('/'); // Redirect to main page
            } else {
                res.send('Incorrect password!'); // If password is wrong, send message
            }
        } else {
            res.send('User not found!'); // If user not found, send message
        }
    });
});

// Admin route
app.get('/admin', (req, res) => {
    if (!req.session.loggedin || !req.session.isAdmin) { // Check if user is logged in and is admin
        return res.redirect('/login'); // Otherwise, redirect to login page
    }
    db.query('SELECT * FROM pqrssi', (err, results) => { // Query all PQRSSI
        if (err) throw err;
        res.render('admin', { pqrssi: results }); // Render admin view with PQRSSI
    });
});

app.post('/admin/change-status', (req, res) => {
    if (!req.session.loggedin || !req.session.isAdmin) { // Check if user is logged in and is admin
        return res.redirect('/login'); // Otherwise, redirect to login page
    }
    const { pqrssi_id, estado_id, comentario } = req.body; // Get form data
    const comentarioCompleto = `Status changed by admin: ${comentario}`; // Prepare full comment

    console.log('Received data:', { pqrssi_id, estado_id, comentario }); // For debugging

    db.query('UPDATE pqrssi SET estado_id = ? WHERE id = ?', [estado_id, pqrssi_id], (err) => { // Update PQRSSI status
        if (err) throw err;

        db.query('INSERT INTO historial (pqrssi_id, estado_id, comentario) VALUES (?, ?, ?)',
            [pqrssi_id, estado_id, comentarioCompleto],
            (err) => {
                if (err) throw err;
                console.log('Stored comment:', comentarioCompleto); // For debugging
                res.redirect('/admin'); // Redirect to admin page
            }
        );
    });
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy(); // Destroy session
    res.redirect('/'); // Redirect to main page
});

// Route to submit a PQRSSI
app.get('/submit', (req, res) => {
    if (!req.session.loggedin) { // Check if user is logged in
        return res.redirect('/login'); // Otherwise, redirect to login page
    }
    db.query('SELECT * FROM categorias', (err, results) => { // Query all categories
        if (err) throw err;
        res.render('submit', { categorias: results }); // Render submit view with categories
    });
});

app.post('/submit', (req, res) => {
    if (!req.session.loggedin) { // Check if user is logged in
        return res.redirect('/login'); // Otherwise, redirect to login page
    }
    const { tipo, descripcion, categoria_id } = req.body; // Get form data
    const usuario_id = req.session.userId; // Use authenticated user ID
    const estado_id = 1; // Initial PQRSSI status

    db.query('INSERT INTO pqrssi (tipo, descripcion, usuario_id, estado_id, categoria_id) VALUES (?, ?, ?, ?, ?)',
        [tipo, descripcion, usuario_id, estado_id, categoria_id],
        (err, result) => {
            if (err) throw err;

            const pqrssi_id = result.insertId; // Get newly created PQRSSI ID

            db.query('INSERT INTO historial (pqrssi_id, estado_id, comentario) VALUES (?, ?, ?)',
                [pqrssi_id, estado_id, 'Request created'],
                (err) => {
                    if (err) throw err;
                    res.redirect('/'); // Redirect to main page
                }
            );
        }
    );
});

// Route to view PQRSSI
app.get('/view', (req, res) => {
    if (!req.session.loggedin) { // Check if user is logged in
        return res.redirect('/login'); // Otherwise, redirect to login page
    }
    db.query(`
        SELECT p.id, p.tipo, p.descripcion, e.nombre AS estado, p.fecha, c.nombre AS categoria, u.nombre AS usuario
        FROM pqrssi p
        JOIN estados e ON p.estado_id = e.id
        JOIN categorias c ON p.categoria_id = c.id
        JOIN usuarios u ON p.usuario_id = u.id
    `, (err, results) => {
        if (err) throw err;
        res.render('view', { pqrssi: results }); // Render view PQRSSI with query results
    });
});

// Route to view PQRSSI history
app.get('/historial/:pqrssi_id', (req, res) => {
    if (!req.session.loggedin) { // Check if user is logged in
        return res.redirect('/login'); // Otherwise, redirect to login page
    }
    const pqrssi_id = req.params.pqrssi_id; // Get PQRSSI ID from URL params

    db.query(`
        SELECT h.id, h.fecha, e.nombre AS estado, h.comentario
        FROM historial h
        JOIN estados e ON h.estado_id = e.id
        WHERE h.pqrssi_id = ?
    `, [pqrssi_id], (err, results) => {
        if (err) throw err;
        res.render('historial', { historial: results }); // Render history view with query results
    });
});

// Start the server on port 3000
app.listen(3000, () => {
    console.log('Server running on port 3000'); // Confirmation message that the server is running
});
