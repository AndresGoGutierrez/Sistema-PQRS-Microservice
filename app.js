const express = require('express'); // Importa el módulo express
const mysql = require('mysql'); // Importa el módulo mysql
const path = require('path'); // Importa el módulo path
const bodyParser = require('body-parser'); // Importa el módulo body-parser
const session = require('express-session'); // Importa el módulo express-session
const bcrypt = require('bcrypt'); // Importa el módulo bcrypt para hashing de contraseñas
const config = require('./config'); // Importa el archivo config.js para las credenciales de la base de datos

const app = express(); // Crea una instancia de express

const db = mysql.createConnection(config); // Crea una conexión a la base de datos usando la configuración del archivo config.js

db.connect(err => { // Conecta a la base de datos
    if (err) {
        console.error('Error connecting to the database:', err.stack);
        return;
    }
    console.log('Connected to the database'); // Mensaje de confirmación de conexión exitosa
});

app.set('view engine', 'ejs'); // Configura el motor de plantillas a EJS
app.set('views', path.join(__dirname, 'views')); // Configura la ruta de las vistas

app.use(bodyParser.urlencoded({ extended: false })); // Configura el body-parser para analizar datos URL-encoded
app.use(express.static(path.join(__dirname, 'public'))); // Configura la carpeta de archivos estáticos

app.use(session({ // Configura las sesiones
    secret: 'your_secret_key', // Llave secreta para firmar la sesión
    resave: false, // No guarda la sesión si no hay cambios
    saveUninitialized: true // Guarda una sesión nueva y vacía
}));



// Ruta principal
app.get('/', (req, res) => {
    res.render('index', { nombre: req.session.nombre, isAdmin: req.session.isAdmin }); // Renderiza la vista index y pasa el nombre de usuario de la sesión
});

// Ruta de registro
app.get('/register', (req, res) => {
    res.render('register'); // Renderiza la vista de registro
});

app.post('/register', async (req, res) => {
    const { nombre, email, contraseña } = req.body; // Obtiene los datos del formulario
    const hashedPassword = await bcrypt.hash(contraseña, 10); // Hashea la contraseña

    var contraseñaRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()+,.?":{}|<>]).{8,}$/;


    if (!contraseñaRegex.test(contraseña)) {
        return res.send("La contraseña debe tener al menos 8 caracteres y contener al menos una letra mayúscula, una letra minúscula, un número y un carácter especial.")
    } else {
        db.query('SELECT * FROM usuarios WHERE email = ?', [email], (err, results) => {
            if (err) throw err;
            if (results.length > 0) {
                return res.send('El email ya está registrado'); // Si el email ya existe, envía un mensaje
            } else {
                db.query('INSERT INTO usuarios (nombre, email, contraseña) VALUES (?, ?, ?)',
                    [nombre, email, hashedPassword],
                    (err, result) => {
                        if (err) throw err;
                        res.redirect('/login'); // Redirige a la página de login
                    });
            }
        });
    }
});

// Ruta de inicio de sesión
app.get('/login', (req, res) => {
    res.render('login'); // Renderiza la vista de login
});

app.post('/login', (req, res) => {
    const { email, contraseña } = req.body; // Obtiene los datos del formulario
    db.query('SELECT * FROM usuarios WHERE email = ?', [email], async (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            const user = results[0];
            if (await bcrypt.compare(contraseña, user.contraseña)) { // Compara la contraseña hasheada
                req.session.loggedin = true; // Marca la sesión como iniciada
                req.session.nombre = user.nombre; // Guarda el nombre del usuario en la sesión
                req.session.userId = user.id; // Guarda el ID del usuario en la sesión
                req.session.isAdmin = user.is_admin; // Guarda si el usuario es administrador en la sesión
                res.redirect('/'); // Redirige a la página principal
            } else {
                res.send('Contraseña incorrecta!'); // Si la contraseña es incorrecta, envía un mensaje
            }
        } else {
            res.send('Usuario no encontrado!'); // Si el usuario no se encuentra, envía un mensaje
        }
    });
});

// Ruta de administrador
app.get('/admin', (req, res) => {
    if (!req.session.loggedin || !req.session.isAdmin) { // Verifica si el usuario está logueado y es administrador
        return res.redirect('/login'); // Si no, redirige a la página de login
    }
    db.query('SELECT * FROM pqrssi', (err, results) => { // Consulta todas las PQRSSI
        if (err) throw err;
        res.render('admin', { pqrssi: results }); // Renderiza la vista de administrador con las PQRSSI
    });
});

app.post('/admin/change-status', (req, res) => {
    if (!req.session.loggedin || !req.session.isAdmin) { // Verifica si el usuario está logueado y es administrador
        return res.redirect('/login'); // Si no, redirige a la página de login
    }
    const { pqrssi_id, estado_id, comentario } = req.body; // Obtiene los datos del formulario
    const comentarioCompleto = `Estado cambiado por administrador: ${comentario}`; // Prepara el comentario completo

    console.log('Datos recibidos:', { pqrssi_id, estado_id, comentario }); // Para depuración

    db.query('UPDATE pqrssi SET estado_id = ? WHERE id = ?', [estado_id, pqrssi_id], (err) => { // Actualiza el estado de la PQRSSI
        if (err) throw err;

        db.query('INSERT INTO historial (pqrssi_id, estado_id, comentario) VALUES (?, ?, ?)',
            [pqrssi_id, estado_id, comentarioCompleto],
            (err) => {
                if (err) throw err;
                console.log('Comentario almacenado:', comentarioCompleto); // Para depuración
                res.redirect('/admin'); // Redirige a la página de administrador
            }
        );
    });
});

// Ruta de cierre de sesión
app.get('/logout', (req, res) => {
    req.session.destroy(); // Destruye la sesión
    res.redirect('/'); // Redirige a la página principal
});

// Ruta para enviar una PQRSSI
app.get('/submit', (req, res) => {
    if (!req.session.loggedin) { // Verifica si el usuario está logueado
        return res.redirect('/login'); // Si no, redirige a la página de login
    }
    db.query('SELECT * FROM categorias', (err, results) => { // Consulta todas las categorías
        if (err) throw err;
        res.render('submit', { categorias: results }); // Renderiza la vista de enviar PQRSSI con las categorías
    });
});

app.post('/submit', (req, res) => {
    if (!req.session.loggedin) { // Verifica si el usuario está logueado
        return res.redirect('/login'); // Si no, redirige a la página de login
    }
    const { tipo, descripcion, categoria_id } = req.body; // Obtiene los datos del formulario
    const usuario_id = req.session.userId; // Usa el ID del usuario autenticado
    const estado_id = 1; // Estado inicial de la PQRSSI

    db.query('INSERT INTO pqrssi (tipo, descripcion, usuario_id, estado_id, categoria_id) VALUES (?, ?, ?, ?, ?)',
        [tipo, descripcion, usuario_id, estado_id, categoria_id],
        (err, result) => {
            if (err) throw err;

            const pqrssi_id = result.insertId; // Obtiene el ID de la PQRSSI recién creada

            db.query('INSERT INTO historial (pqrssi_id, estado_id, comentario) VALUES (?, ?, ?)',
                [pqrssi_id, estado_id, 'Solicitud creada'],
                (err) => {
                    if (err) throw err;
                    res.redirect('/'); // Redirige a la página principal
                }
            );
        }
    );
});

// Ruta para ver las PQRSSI
app.get('/view', (req, res) => {
    if (!req.session.loggedin) { // Verifica si el usuario está logueado
        return res.redirect('/login'); // Si no, redirige a la página de login
    }
    db.query(`
        SELECT p.id, p.tipo, p.descripcion, e.nombre AS estado, p.fecha, c.nombre AS categoria, u.nombre AS usuario
        FROM pqrssi p
        JOIN estados e ON p.estado_id = e.id
        JOIN categorias c ON p.categoria_id = c.id
        JOIN usuarios u ON p.usuario_id = u.id
    `, (err, results) => {
        if (err) throw err;
        res.render('view', { pqrssi: results }); // Renderiza la vista de ver PQRSSI con los resultados de la consulta
    });
});

// Ruta para ver el historial de una PQRSSI
app.get('/historial/:pqrssi_id', (req, res) => {
    if (!req.session.loggedin) { // Verifica si el usuario está logueado
        return res.redirect('/login'); // Si no, redirige a la página de login
    }
    const pqrssi_id = req.params.pqrssi_id; // Obtiene el ID de la PQRSSI de los parámetros de la URL

    db.query(`
        SELECT h.id, h.fecha, e.nombre AS estado, h.comentario
        FROM historial h
        JOIN estados e ON h.estado_id = e.id
        WHERE h.pqrssi_id = ?
    `, [pqrssi_id], (err, results) => {
        if (err) throw err;
        res.render('historial', { historial: results }); // Renderiza la vista de historial con los resultados de la consulta
    });
});

// Inicia el servidor en el puerto 3000
app.listen(3000, () => {
    console.log('Server running on port 3000'); // Mensaje de confirmación de que el servidor está corriendo
});
