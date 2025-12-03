

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();



const http = require('http');
const { Server } = require('socket.io');


const server = http.createServer(app);


const urlFront = process.env.URL_FRONT;
const io = new Server(server, {
  cors: {
    origin: urlFront,
    methods: ["GET", "POST"],
    credentials: true
  }
});

app.use(express.json());

app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://tu-frontend-en-render.com',
    process.env.URL_FRONT
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const JWT_SECRET = process.env.JWT_SECRET;



const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
});

pool.getConnection()
  .then(connection => {
    console.log('Conexión exitosa a MySQL (XAMPP)');
    connection.release();
  })
  .catch(err => {
    console.error('Error conectando a MySQL:', err.message);
    console.error('Verifica que:');
    console.error('1. XAMPP esté corriendo');
    console.error('2. MySQL esté iniciado en XAMPP');
    console.error('3. Las credenciales en .env sean correctas');
    console.error('4. La base de datos "dbt" exista');
  });


const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};


const checkRole = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.rol)) {
      return res.status(403).json({ error: 'No tienes permisos' });
    }
    next();
  };
};


app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    console.log('Intento de login para:', username);
    console.log('Datos recibidos:', { username, password: '***' });

    const [users] = await pool.query(
      'SELECT * FROM USUARIO WHERE username = ? AND activo = TRUE',
      [username]
    );

    console.log('Usuarios encontrados:', users.length);

    if (users.length === 0) {
      console.log('Usuario no encontrado o inactivo');
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    const user = users[0];
    console.log('Usuario encontrado:', user.username);
    console.log('Hash en BD:', user.password_hash);

    const validPassword = await bcrypt.compare(password, user.password_hash);
    console.log('Contraseña válida:', validPassword);

    if (!validPassword) {
      console.log('Contraseña incorrecta');
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    console.log('Login exitoso para:', user.username);


    await pool.query(
      'UPDATE USUARIO SET ultimo_acceso = NOW() WHERE id_usuario = ?',
      [user.id_usuario]
    );


    await pool.query(
      'INSERT INTO AUDITORIA (id_usuario, accion, descripcion, ip_address) VALUES (?, ?, ?, ?)',
      [user.id_usuario, 'login', 'Inicio de sesión exitoso', req.ip]
    );

    const token = jwt.sign(
      { 
        id: user.id_usuario, 
        username: user.username, 
        rol: user.rol 
      },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      token,
      usuario: {
        id: user.id_usuario,
        username: user.username,
        nombre_completo: user.nombre_completo,
        rol: user.rol,
        debe_cambiar_password: user.debe_cambiar_password
      }
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error en el servidor' });
  }
});


app.post('/api/auth/cambiar-password', authenticateToken, async (req, res) => {
  try {
    const { password_actual, password_nueva } = req.body;

    const [users] = await pool.query(
      'SELECT password_hash FROM USUARIO WHERE id_usuario = ?',
      [req.user.id]
    );

    const validPassword = await bcrypt.compare(password_actual, users[0].password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }

    const hash = await bcrypt.hash(password_nueva, 10);

    await pool.query(
      'UPDATE USUARIO SET password_hash = ?, debe_cambiar_password = FALSE WHERE id_usuario = ?',
      [hash, req.user.id]
    );

    res.json({ mensaje: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al cambiar contraseña' });
  }
});


app.get('/api/usuarios', authenticateToken, checkRole('admin'), async (req, res) => {
  try {
    const [usuarios] = await pool.query(
      'SELECT id_usuario, username, nombre_completo, email, rol, activo, ultimo_acceso, fecha_creacion FROM USUARIO ORDER BY fecha_creacion DESC'
    );
    res.json(usuarios);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener usuarios' });
  }
});


app.post('/api/usuarios', authenticateToken, checkRole('admin'), async (req, res) => {
  try {
    const { username, nombre_completo, email, rol } = req.body;
    

    const password_temporal = Math.random().toString(36).slice(-8);
    const hash = await bcrypt.hash(password_temporal, 10);

    const [result] = await pool.query(
      'INSERT INTO USUARIO (username, password_hash, nombre_completo, email, rol, creado_por, debe_cambiar_password) VALUES (?, ?, ?, ?, ?, ?, TRUE)',
      [username, hash, nombre_completo, email, rol, req.user.id]
    );


    await pool.query(
      'INSERT INTO AUDITORIA (id_usuario, accion, tabla_afectada, id_registro_afectado, descripcion) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, 'crear', 'USUARIO', result.insertId, `Usuario ${username} creado`]
    );

    res.json({
      mensaje: 'Usuario creado exitosamente',
      usuario: { id: result.insertId, username },
      password_temporal
    });
  } catch (error) {
    console.error(error);
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'El username ya existe' });
    }
    res.status(500).json({ error: 'Error al crear usuario' });
  }
});


app.put('/api/usuarios/:id', authenticateToken, checkRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { nombre_completo, email, rol, activo } = req.body;

    await pool.query(
      'UPDATE USUARIO SET nombre_completo = ?, email = ?, rol = ?, activo = ? WHERE id_usuario = ?',
      [nombre_completo, email, rol, activo, id]
    );

    res.json({ mensaje: 'Usuario actualizado correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar usuario' });
  }
});


app.delete('/api/usuarios/:id', authenticateToken, checkRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    
    await pool.query('DELETE FROM USUARIO WHERE id_usuario = ?', [id]);
    
    res.json({ mensaje: 'Usuario eliminado correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al eliminar usuario' });
  }
});



app.get('/api/ninos', authenticateToken, async (req, res) => {
  try {
    const [ninos] = await pool.query(
      `SELECT n.*, 
              COUNT(DISTINCT t.id_tamizaje) as total_tamizajes,
              MAX(t.fecha) as ultimo_tamizaje
       FROM NINO n
       LEFT JOIN TAMIZAJE_OJO t ON n.id_nino = t.id_nino
       GROUP BY n.id_nino
       ORDER BY n.fecha_registro DESC`
    );
    res.json(ninos);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener niños' });
  }
});


app.get('/api/ninos/buscar', authenticateToken, async (req, res) => {
  try {
    const { termino, fecha } = req.query;
    
    let query = `
      SELECT n.*, 
             COUNT(DISTINCT t.id_tamizaje) as total_tamizajes,
             MAX(t.fecha) as ultimo_tamizaje
      FROM NINO n
      LEFT JOIN TAMIZAJE_OJO t ON n.id_nino = t.id_nino
      WHERE 1=1
    `;
    
    const params = [];

    if (termino) {
      query += ` AND (
        n.nombres_nino LIKE ? OR 
        n.paterno_nino LIKE ? OR 
        n.materno_nino LIKE ? OR
        n.carnet_nino LIKE ?
      )`;
      const terminoBusqueda = `%${termino}%`;
      params.push(terminoBusqueda, terminoBusqueda, terminoBusqueda, terminoBusqueda);
    }

    if (fecha) {
      query += ` AND DATE(n.fecha_nacimiento) = ?`;
      params.push(fecha);
    }

    query += ` GROUP BY n.id_nino ORDER BY n.fecha_registro DESC`;

    const [ninos] = await pool.query(query, params);
    res.json(ninos);

  } catch (error) {
    console.error('Error al buscar niños:', error);
    res.status(500).json({ error: 'Error al buscar niños' });
  }
});


app.get('/api/ninos/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const [nino] = await pool.query('SELECT * FROM NINO WHERE id_nino = ?', [id]);
    
    if (nino.length === 0) {
      return res.status(404).json({ error: 'Niño no encontrado' });
    }

    const [tutores] = await pool.query(
      `SELECT t.*, hr.parentesco, hr.es_tutor_principal
       FROM TUTOR t
       INNER JOIN HACE_REVISAR_A hr ON t.id_tutor = hr.id_tutor
       WHERE hr.id_nino = ?`,
      [id]
    );

  
    const [tamizajes] = await pool.query(
      `SELECT id_tamizaje, fecha, ojo, estado, 
              niveles_superados, aciertos_totales, porcentaje_aciertos,
              tiempo_promedio, consistencia, error_vertical, error_horizontal,
              diagnostico_preliminar, fecha_registro
       FROM TAMIZAJE_OJO
       WHERE id_nino = ?
       ORDER BY fecha DESC`,
      [id]
    );

    res.json({
      nino: nino[0],
      tutores,
      tamizajes
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al obtener datos del niño' });
  }
});


app.post('/api/ninos', authenticateToken, checkRole('admin', 'operador'), async (req, res) => {
  try {
    const { 
      carnet_nino, nombres_nino, paterno_nino, materno_nino,
      fecha_nacimiento, genero, url_imagen, observaciones
    } = req.body;

    const [result] = await pool.query(
      `INSERT INTO NINO 
       (carnet_nino, nombres_nino, paterno_nino, materno_nino, fecha_nacimiento, genero, url_imagen, observaciones, registrado_por)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [carnet_nino, nombres_nino, paterno_nino, materno_nino, fecha_nacimiento, genero, url_imagen, observaciones, req.user.id]
    );

    res.json({
      mensaje: 'Niño registrado exitosamente',
      id_nino: result.insertId
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar niño' });
  }
});


app.put('/api/ninos/:id', authenticateToken, checkRole('admin', 'operador'), async (req, res) => {
  try {
    const { id } = req.params;
    const campos = req.body;
    
    const sets = Object.keys(campos).map(key => `${key} = ?`).join(', ');
    const valores = [...Object.values(campos), id];

    await pool.query(
      `UPDATE NINO SET ${sets} WHERE id_nino = ?`,
      valores
    );

    res.json({ mensaje: 'Datos actualizados correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar niño' });
  }
});

app.post('/api/unity/tamizaje', async (req, res) => {
  try {
    const { child, trials } = req.body;

    let id_nino;
    const [existeNino] = await pool.query(
      'SELECT id_nino FROM NINO WHERE carnet_nino = ?',
      [child.carnet]
    );

    if (existeNino.length > 0) {
      id_nino = existeNino[0].id_nino;
    } else {
      const [nuevoNino] = await pool.query(
        'INSERT INTO NINO (carnet_nino, nombres_nino, paterno_nino, materno_nino, fecha_nacimiento, genero) VALUES (?, ?, ?, ?, ?, ?)',
        [child.carnet, child.nombres, child.paterno, child.materno, child.fechaNacimiento, child.genero]
      );
      id_nino = nuevoNino.insertId;
    }

    const ojosUnicos = [...new Set(trials.map(t => t.eye))];
    
    for (const ojo of ojosUnicos) {
      const trialsOjo = trials.filter(t => t.eye === ojo);
      
      const aciertos = trialsOjo.filter(t => t.correct === 1).length;
      const porcentaje = (aciertos / trialsOjo.length * 100).toFixed(2);
      const tiempoPromedio = (trialsOjo.reduce((sum, t) => sum + parseFloat(t.reactionTime), 0) / trialsOjo.length).toFixed(3);
      const nivelesUnicos = [...new Set(trialsOjo.map(t => t.level))];

      const [tamizaje] = await pool.query(
        `INSERT INTO TAMIZAJE_OJO 
         (id_nino, fecha, ojo, estado, niveles_superados, aciertos_totales, porcentaje_aciertos, tiempo_promedio)
         VALUES (?, NOW(), ?, 'completado', ?, ?, ?, ?)`,
        [id_nino, ojo, nivelesUnicos.length, aciertos, porcentaje, tiempoPromedio]
      );

      for (const trial of trialsOjo) {
        await pool.query(
          'INSERT INTO EXAMEN (nivel, direccion_mostrada, respuesta, correcto, tiempo, id_tamizaje) VALUES (?, ?, ?, ?, ?, ?)',
          [trial.level, trial.directionShown, trial.response, trial.correct, trial.reactionTime, tamizaje.insertId]
        );
      }
    }

    res.json({ 
      mensaje: 'Tamizaje registrado correctamente',
      id_nino 
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al procesar tamizaje de Unity' });
  }
});

app.post('/api/ia/predecir-error', authenticateToken, async (req, res) => {
  try {
    const { id_tamizaje } = req.body;

    const [tamizaje] = await pool.query(
      `SELECT * FROM TAMIZAJE_OJO WHERE id_tamizaje = ?`,
      [id_tamizaje]
    );

    if (tamizaje.length === 0) {
      return res.status(404).json({ error: 'Tamizaje no encontrado' });
    }

    res.json({
      mensaje: 'Funcionalidad de IA pendiente de implementación',
      nota: 'Se implementará cuando tengas el microservicio Python listo'
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al consultar IA' });
  }
});


app.get('/api/health', async (req, res) => {
  try {
    const [result] = await pool.query('SELECT 1 as ok');
    res.json({ 
      status: 'OK', 
      database: 'Conectado',
      timestamp: new Date(),
      message: 'Backend funcionando correctamente'
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'ERROR', 
      database: 'Desconectado',
      error: error.message,
      timestamp: new Date()
    });
  }
});

app.post('/api/ninos/completo', authenticateToken, checkRole('admin', 'operador'), async (req, res) => {
  let connection;
  
  try {
    const { nino, tutor, tamizaje_oid, tamizaje_oi } = req.body;

    
    if (!nino || !nino.nombres_nino || !nino.nombres_nino.trim()) {
      return res.status(400).json({ 
        error: 'El nombre del niño es obligatorio' 
      });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();


    const [resultNino] = await connection.query(
      `INSERT INTO NINO 
       (carnet_nino, nombres_nino, paterno_nino, materno_nino, fecha_nacimiento, genero, url_imagen, observaciones, registrado_por)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        nino.carnet_nino || null,
        nino.nombres_nino,
        nino.paterno_nino || null,
        nino.materno_nino || null,
        nino.fecha_nacimiento || null,
        nino.genero || null,
        nino.url_imagen || null,
        nino.observaciones || null,
        req.user.id
      ]
    );

    const id_nino = resultNino.insertId;


    let id_tutor = null;
    if (tutor && tutor.nombre_tutor && tutor.nombre_tutor.trim()) {
      const [resultTutor] = await connection.query(
        `INSERT INTO TUTOR 
         (carnet_tutor, nombre_tutor, paterno_tutor, materno_tutor, celular, email)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          tutor.carnet_tutor || null,
          tutor.nombre_tutor,
          tutor.paterno_tutor || null,
          tutor.materno_tutor || null,
          tutor.celular || null,
          tutor.email || null
        ]
      );

      id_tutor = resultTutor.insertId;

      await connection.query(
        `INSERT INTO HACE_REVISAR_A 
         (id_nino, id_tutor, parentesco, es_tutor_principal, fecha_registro)
         VALUES (?, ?, ?, ?, NOW())`,
        [
          id_nino,
          id_tutor,
          tutor.parentesco || 'No especificado',
          tutor.es_tutor_principal !== undefined ? tutor.es_tutor_principal : true
        ]
      );
    }

    const tamizajes = [];

    const toNumberOrNull = (value) => {
      if (value === '' || value === null || value === undefined) return null;
      const num = parseFloat(value);
      return isNaN(num) ? null : num;
    };


    if (tamizaje_oid && tamizaje_oid.fecha) {
      const [resultTamizajeOD] = await connection.query(
        `INSERT INTO TAMIZAJE_OJO 
         (id_nino, id_tutor, estado, fecha, ojo, niveles_superados, aciertos_totales, 
          porcentaje_aciertos, tiempo_promedio, consistencia, error_vertical, error_horizontal,
          diagnostico_preliminar)
         VALUES (?, ?, ?, ?, 'DERECHO', ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id_nino,
          id_tutor, 
          tamizaje_oid.estado || 'completado',
          tamizaje_oid.fecha,
          toNumberOrNull(tamizaje_oid.niveles_superados),
          toNumberOrNull(tamizaje_oid.aciertos_totales),
          toNumberOrNull(tamizaje_oid.porcentaje_aciertos),
          toNumberOrNull(tamizaje_oid.tiempo_promedio),
          tamizaje_oid.consistencia || null,
          toNumberOrNull(tamizaje_oid.error_vertical),
          toNumberOrNull(tamizaje_oid.error_horizontal),
          tamizaje_oid.diagnostico_preliminar || null
        ]
      );
      tamizajes.push({ ojo: 'DERECHO', id: resultTamizajeOD.insertId });
    }


    if (tamizaje_oi && tamizaje_oi.fecha) {
      const [resultTamizajeOI] = await connection.query(
        `INSERT INTO TAMIZAJE_OJO 
         (id_nino, id_tutor, estado, fecha, ojo, niveles_superados, aciertos_totales, 
          porcentaje_aciertos, tiempo_promedio, consistencia, error_vertical, error_horizontal,
          diagnostico_preliminar)
         VALUES (?, ?, ?, ?, 'IZQUIERDO', ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id_nino,
          id_tutor, 
          tamizaje_oi.estado || 'completado',
          tamizaje_oi.fecha,
          toNumberOrNull(tamizaje_oi.niveles_superados),
          toNumberOrNull(tamizaje_oi.aciertos_totales),
          toNumberOrNull(tamizaje_oi.porcentaje_aciertos),
          toNumberOrNull(tamizaje_oi.tiempo_promedio),
          tamizaje_oi.consistencia || null,
          toNumberOrNull(tamizaje_oi.error_vertical),
          toNumberOrNull(tamizaje_oi.error_horizontal),
          tamizaje_oi.diagnostico_preliminar || null
        ]
      );
      tamizajes.push({ ojo: 'IZQUIERDO', id: resultTamizajeOI.insertId });
    }

    await connection.query(
      'INSERT INTO AUDITORIA (id_usuario, accion, tabla_afectada, id_registro_afectado, descripcion) VALUES (?, ?, ?, ?, ?)',
      [
        req.user.id,
        'crear',
        'NINO',
        id_nino,
        `Niño ${nino.nombres_nino} registrado con ${tutor ? 'tutor' : 'sin tutor'} y ${tamizajes.length} tamizaje(s)`
      ]
    );

    await connection.commit();

    res.json({
      mensaje: 'Niño registrado exitosamente',
      id_nino: id_nino,
      id_tutor: id_tutor,
      tamizajes: tamizajes,
      detalle: {
        nino_creado: true,
        tutor_creado: id_tutor !== null,
        tamizajes_creados: tamizajes.length
      }
    });

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Error al registrar niño completo:', error);
    
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ 
        error: 'El carnet del niño o tutor ya existe en el sistema' 
      });
    }
    
    res.status(500).json({ 
      error: 'Error al registrar el niño completo',
      detalle: error.message 
    });
  } finally {
    if (connection) connection.release();
  }
});


app.get('/api/permisos/mis-permisos', authenticateToken, async (req, res) => {
  try {
    const [permisos] = await pool.query(
      'SELECT * FROM PERMISOS WHERE id_usuario = ?',
      [req.user.id]
    );

    if (permisos.length === 0) {
      const permisosDefault = {
        puede_crear_ninos: req.user.rol === 'admin' || req.user.rol === 'operador',
        puede_editar_ninos: req.user.rol === 'admin' || req.user.rol === 'operador',
        puede_eliminar_ninos: req.user.rol === 'admin',
        puede_ver_reportes: true,
        puede_exportar_datos: req.user.rol === 'admin' || req.user.rol === 'doctor',
        puede_gestionar_usuarios: req.user.rol === 'admin'
      };
      return res.json(permisosDefault);
    }

    res.json(permisos[0]);
  } catch (error) {
    console.error('Error al obtener permisos:', error);
    res.status(500).json({ error: 'Error al obtener permisos' });
  }
});



app.put('/api/ninos/:id/actualizar-completo', authenticateToken, checkRole('admin', 'operador'), async (req, res) => {
  let connection;
  
  try {
    const { id } = req.params;
    const { nino, tutor, tamizaje_oid, tamizaje_oi } = req.body;

    connection = await pool.getConnection();
    await connection.beginTransaction();

    if (nino) {
      const camposNino = [];
      const valoresNino = [];
      const camposExcluidosNino = [
        'id_nino', 
        'fecha_registro', 
        'fecha_modificacion', 
        'registrado_por'
      ];

      Object.keys(nino).forEach(key => {
        if (!camposExcluidosNino.includes(key)) {
          camposNino.push(`${key} = ?`);
          valoresNino.push(nino[key] || null);
        }
      });

      if (camposNino.length > 0) {
        valoresNino.push(id);
        await connection.query(
          `UPDATE NINO SET ${camposNino.join(', ')} WHERE id_nino = ?`,
          valoresNino
        );
      }
    }

    if (tutor && tutor.id_tutor) {
      const camposTutor = [];
      const valoresTutor = [];

      const camposExcluidosTutor = [
        'id_tutor', 
        'parentesco', 
        'es_tutor_principal', 
        'fecha_registro', 
        'fecha_modificacion'
      ];

      Object.keys(tutor).forEach(key => {
        if (!camposExcluidosTutor.includes(key)) {
          camposTutor.push(`${key} = ?`);
          valoresTutor.push(tutor[key] || null);
        }
      });

      if (camposTutor.length > 0) {
        valoresTutor.push(tutor.id_tutor);
        await connection.query(
          `UPDATE TUTOR SET ${camposTutor.join(', ')} WHERE id_tutor = ?`,
          valoresTutor
        );
      }

      if (tutor.parentesco !== undefined || tutor.es_tutor_principal !== undefined) {
        await connection.query(
          `UPDATE HACE_REVISAR_A 
           SET parentesco = COALESCE(?, parentesco), 
               es_tutor_principal = COALESCE(?, es_tutor_principal)
           WHERE id_nino = ? AND id_tutor = ?`,
          [tutor.parentesco, tutor.es_tutor_principal, id, tutor.id_tutor]
        );
      }
    }

    const toNumberOrNull = (value) => {
      if (value === '' || value === null || value === undefined) return null;
      const num = parseFloat(value);
      return isNaN(num) ? null : num;
    };

    const toDateOrNull = (value) => {
      if (!value || value === '') return null;
      if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
        return value;
      }
      if (value.includes('T')) {
        return value.split('T')[0];
      }
      return value;
    };

    if (tamizaje_oid && tamizaje_oid.id_tamizaje) {
      const camposTamizaje = [];
      const valoresTamizaje = [];

      const camposExcluidosTamizaje = [
        'id_tamizaje', 
        'ojo', 
        'fecha_registro', 
        'fecha_modificacion',
        'id_nino',
        'id_tutor'
      ];

      Object.keys(tamizaje_oid).forEach(key => {
        if (!camposExcluidosTamizaje.includes(key)) {
          camposTamizaje.push(`${key} = ?`);
          
          if (key === 'fecha') {
            valoresTamizaje.push(toDateOrNull(tamizaje_oid[key]));
          } else if (['niveles_superados', 'aciertos_totales', 'porcentaje_aciertos', 
                      'tiempo_promedio', 'error_vertical', 'error_horizontal'].includes(key)) {
            valoresTamizaje.push(toNumberOrNull(tamizaje_oid[key]));
          } else {
            valoresTamizaje.push(tamizaje_oid[key] || null);
          }
        }
      });

      if (camposTamizaje.length > 0) {
        valoresTamizaje.push(tamizaje_oid.id_tamizaje);
        await connection.query(
          `UPDATE TAMIZAJE_OJO SET ${camposTamizaje.join(', ')} WHERE id_tamizaje = ?`,
          valoresTamizaje
        );
      }
    }

    if (tamizaje_oi && tamizaje_oi.id_tamizaje) {
      const camposTamizaje = [];
      const valoresTamizaje = [];

      const camposExcluidosTamizaje = [
        'id_tamizaje', 
        'ojo', 
        'fecha_registro', 
        'fecha_modificacion',
        'id_nino',
        'id_tutor'
      ];

      Object.keys(tamizaje_oi).forEach(key => {
        if (!camposExcluidosTamizaje.includes(key)) {
          camposTamizaje.push(`${key} = ?`);
          
          if (key === 'fecha') {
            valoresTamizaje.push(toDateOrNull(tamizaje_oi[key]));
          } else if (['niveles_superados', 'aciertos_totales', 'porcentaje_aciertos', 
                      'tiempo_promedio', 'error_vertical', 'error_horizontal'].includes(key)) {
            valoresTamizaje.push(toNumberOrNull(tamizaje_oi[key]));
          } else {
            valoresTamizaje.push(tamizaje_oi[key] || null);
          }
        }
      });

      if (camposTamizaje.length > 0) {
        valoresTamizaje.push(tamizaje_oi.id_tamizaje);
        await connection.query(
          `UPDATE TAMIZAJE_OJO SET ${camposTamizaje.join(', ')} WHERE id_tamizaje = ?`,
          valoresTamizaje
        );
      }
    }

    await connection.query(
      'INSERT INTO AUDITORIA (id_usuario, accion, tabla_afectada, id_registro_afectado, descripcion) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, 'editar', 'NINO', id, `Actualización de datos del niño ID ${id}`]
    );

    await connection.commit();

    res.json({ 
      mensaje: 'Datos actualizados correctamente',
      id_nino: id
    });

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Error al actualizar niño completo:', error);
    res.status(500).json({ 
      error: 'Error al actualizar los datos',
      detalle: error.message 
    });
  } finally {
    if (connection) connection.release();
  }
});


app.delete('/api/ninos/:id', authenticateToken, checkRole('admin'), async (req, res) => {
  let connection;
  
  try {
    const { id } = req.params;

    const [nino] = await pool.query('SELECT nombres_nino, paterno_nino FROM NINO WHERE id_nino = ?', [id]);
    
    if (nino.length === 0) {
      return res.status(404).json({ error: 'Niño no encontrado' });
    }

    connection = await pool.getConnection();
    await connection.beginTransaction();

    await connection.query(
      'INSERT INTO AUDITORIA (id_usuario, accion, tabla_afectada, id_registro_afectado, descripcion) VALUES (?, ?, ?, ?, ?)',
      [
        req.user.id, 
        'eliminar', 
        'NINO', 
        id, 
        `Eliminación del niño: ${nino[0].nombres_nino} ${nino[0].paterno_nino || ''}`
      ]
    );
    await connection.query('DELETE FROM NINO WHERE id_nino = ?', [id]);

    await connection.commit();

    res.json({ 
      mensaje: 'Niño eliminado correctamente',
      nombre: `${nino[0].nombres_nino} ${nino[0].paterno_nino || ''}`
    });

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Error al eliminar niño:', error);
    res.status(500).json({ 
      error: 'Error al eliminar el niño',
      detalle: error.message 
    });
  } finally {
    if (connection) connection.release();
  }
});


app.get('/api/permisos/usuario/:id', authenticateToken, checkRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    
    const [permisos] = await pool.query(
      'SELECT * FROM PERMISOS WHERE id_usuario = ?',
      [id]
    );

    if (permisos.length === 0) {
      const [usuario] = await pool.query(
        'SELECT rol FROM USUARIO WHERE id_usuario = ?',
        [id]
      );

      if (usuario.length === 0) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const permisosDefecto = {
        admin: {
          puede_crear_ninos: true,
          puede_editar_ninos: true,
          puede_eliminar_ninos: true,
          puede_ver_reportes: true,
          puede_exportar_datos: true,
          puede_gestionar_usuarios: true
        },
        operador: {
          puede_crear_ninos: true,
          puede_editar_ninos: true,
          puede_eliminar_ninos: false,
          puede_ver_reportes: true,
          puede_exportar_datos: false,
          puede_gestionar_usuarios: false
        },
        doctor: {
          puede_crear_ninos: false,
          puede_editar_ninos: false,
          puede_eliminar_ninos: false,
          puede_ver_reportes: true,
          puede_exportar_datos: true,
          puede_gestionar_usuarios: false
        },
        visualizador: {
          puede_crear_ninos: false,
          puede_editar_ninos: false,
          puede_eliminar_ninos: false,
          puede_ver_reportes: true,
          puede_exportar_datos: false,
          puede_gestionar_usuarios: false
        }
      };

      return res.json(permisosDefecto[usuario[0].rol] || permisosDefecto.visualizador);
    }

    res.json(permisos[0]);
  } catch (error) {
    console.error('Error al obtener permisos:', error);
    res.status(500).json({ error: 'Error al obtener permisos del usuario' });
  }
});

app.put('/api/permisos/usuario/:id', authenticateToken, checkRole('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      puede_crear_ninos,
      puede_editar_ninos,
      puede_eliminar_ninos,
      puede_ver_reportes,
      puede_exportar_datos,
      puede_gestionar_usuarios
    } = req.body;

    const [permisosExistentes] = await pool.query(
      'SELECT id_permiso FROM PERMISOS WHERE id_usuario = ?',
      [id]
    );

    if (permisosExistentes.length > 0) {
      await pool.query(
        `UPDATE PERMISOS SET 
         puede_crear_ninos = ?, 
         puede_editar_ninos = ?, 
         puede_eliminar_ninos = ?, 
         puede_ver_reportes = ?, 
         puede_exportar_datos = ?, 
         puede_gestionar_usuarios = ?
         WHERE id_usuario = ?`,
        [
          puede_crear_ninos,
          puede_editar_ninos,
          puede_eliminar_ninos,
          puede_ver_reportes,
          puede_exportar_datos,
          puede_gestionar_usuarios,
          id
        ]
      );
    } else {
      await pool.query(
        `INSERT INTO PERMISOS 
         (id_usuario, puede_crear_ninos, puede_editar_ninos, puede_eliminar_ninos, 
          puede_ver_reportes, puede_exportar_datos, puede_gestionar_usuarios)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          puede_crear_ninos,
          puede_editar_ninos,
          puede_eliminar_ninos,
          puede_ver_reportes,
          puede_exportar_datos,
          puede_gestionar_usuarios
        ]
      );
    }

    await pool.query(
      'INSERT INTO AUDITORIA (id_usuario, accion, tabla_afectada, id_registro_afectado, descripcion) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, 'editar', 'PERMISOS', id, `Actualización de permisos del usuario ID ${id}`]
    );

    res.json({ mensaje: 'Permisos actualizados correctamente' });
  } catch (error) {
    console.error('Error al actualizar permisos:', error);
    res.status(500).json({ error: 'Error al actualizar permisos' });
  }
});


app.post('/api/usuarios', authenticateToken, checkRole('admin'), async (req, res) => {
  let connection;
  
  try {
    const { username, nombre_completo, email, rol, permisos } = req.body;
    
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    const password_temporal = Math.random().toString(36).slice(-8);
    const hash = await bcrypt.hash(password_temporal, 10);

    const [result] = await connection.query(
      'INSERT INTO USUARIO (username, password_hash, nombre_completo, email, rol, creado_por, debe_cambiar_password) VALUES (?, ?, ?, ?, ?, ?, TRUE)',
      [username, hash, nombre_completo, email, rol, req.user.id]
    );

    const nuevoUsuarioId = result.insertId;

    if (permisos) {
      await connection.query(
        `INSERT INTO PERMISOS 
         (id_usuario, puede_crear_ninos, puede_editar_ninos, puede_eliminar_ninos, 
          puede_ver_reportes, puede_exportar_datos, puede_gestionar_usuarios)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          nuevoUsuarioId,
          permisos.puede_crear_ninos || false,
          permisos.puede_editar_ninos || false,
          permisos.puede_eliminar_ninos || false,
          permisos.puede_ver_reportes !== undefined ? permisos.puede_ver_reportes : true,
          permisos.puede_exportar_datos || false,
          permisos.puede_gestionar_usuarios || false
        ]
      );
    }

    await connection.query(
      'INSERT INTO AUDITORIA (id_usuario, accion, tabla_afectada, id_registro_afectado, descripcion) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, 'crear', 'USUARIO', nuevoUsuarioId, `Usuario ${username} creado con permisos personalizados`]
    );

    await connection.commit();

    res.json({
      mensaje: 'Usuario creado exitosamente',
      usuario: { id: nuevoUsuarioId, username },
      password_temporal
    });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Error al crear usuario:', error);
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'El username ya existe' });
    }
    res.status(500).json({ error: 'Error al crear usuario' });
  } finally {
    if (connection) connection.release();
  }
});

const PDFGenerator = require('./pdfGenerator');
const { CONNREFUSED } = require('dns');

app.get('/api/ninos/:id/pdf', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const [nino] = await pool.query('SELECT * FROM NINO WHERE id_nino = ?', [id]);
    
    if (nino.length === 0) {
      return res.status(404).json({ error: 'Niño no encontrado' });
    }

    const [tutores] = await pool.query(
      `SELECT t.*, hr.parentesco, hr.es_tutor_principal
       FROM TUTOR t
       INNER JOIN HACE_REVISAR_A hr ON t.id_tutor = hr.id_tutor
       WHERE hr.id_nino = ?`,
      [id]
    );

    const [tamizajes] = await pool.query(
      `SELECT id_tamizaje, fecha, ojo, estado, 
              niveles_superados, aciertos_totales, porcentaje_aciertos,
              tiempo_promedio, consistencia, error_vertical, error_horizontal,
              diagnostico_preliminar, fecha_registro
       FROM TAMIZAJE_OJO
       WHERE id_nino = ?
       ORDER BY ojo, fecha DESC`,
      [id]
    );

    const ninoData = {
      nino: nino[0],
      tutores,
      tamizajes
    };

    const pdfBuffer = await PDFGenerator.generarReporteNino(ninoData);

    const nombreArchivo = `reporte_${ninoData.nino.nombres_nino}_${ninoData.nino.paterno_nino || ''}.pdf`
      .toLowerCase()
      .replace(/\s+/g, '_')
      .replace(/[^a-z0-9_]/g, '');

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${nombreArchivo}"`);
    res.setHeader('Content-Length', pdfBuffer.length);

    res.send(pdfBuffer);

    await pool.query(
      'INSERT INTO AUDITORIA (id_usuario, accion, tabla_afectada, id_registro_afectado, descripcion) VALUES (?, ?, ?, ?, ?)',
      [
        req.user.id,
        'exportar',
        'NINO',
        id,
        `PDF descargado para niño: ${ninoData.nino.nombres_nino}`
      ]
    );

  } catch (error) {
    console.error('Error al generar PDF:', error);
    res.status(500).json({ 
      error: 'Error al generar el PDF',
      detalle: error.message 
    });
  }
});

app.get('/api/auth/verificar-token', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id_usuario, username, nombre_completo, email, rol FROM USUARIO WHERE id_usuario = ? AND activo = TRUE',
      [req.user.id]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json(users[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al verificar token' });
  }
});

io.on('connection', (socket) => {
  console.log(`Usuario conectado: ${socket.username} (ID: ${socket.userId})`);
  
  socket.join(`user_${socket.userId}`);
  
  socket.on('disconnect', () => {
    console.log(`Usuario desconectado: ${socket.username}`);
  });
});

app.get('/api/videollamadas', authenticateToken, async (req, res) => {
  try {
    const [videollamadas] = await pool.query(
      `SELECT 
        v.*,
        u.nombre_completo as creador_nombre,
        COUNT(DISTINCT p.id_participante) as total_participantes
       FROM SESION_VIDEOLLAMADA v
       INNER JOIN USUARIO u ON v.creada_por = u.id_usuario
       LEFT JOIN PARTICIPANTES_VIDEOLLAMADA p ON v.id_sesion = p.id_sesion
       WHERE v.creada_por = ? OR v.id_sesion IN (
         SELECT id_sesion FROM PARTICIPANTES_VIDEOLLAMADA WHERE id_usuario = ?
       )
       GROUP BY v.id_sesion
       ORDER BY v.fecha_inicio DESC
       LIMIT 50`,
      [req.user.id, req.user.id]
    );
    
    res.json(videollamadas);
  } catch (error) {
    console.error('Error al obtener videollamadas:', error);
    res.status(500).json({ error: 'Error al obtener videollamadas' });
  }
});

app.get('/api/videollamadas/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [videollamada] = await pool.query(
      `SELECT v.*, u.nombre_completo as creador_nombre
       FROM SESION_VIDEOLLAMADA v
       INNER JOIN USUARIO u ON v.creada_por = u.id_usuario
       WHERE v.id_sesion = ?`,
      [id]
    );
    
    if (videollamada.length === 0) {
      return res.status(404).json({ error: 'Videollamada no encontrada' });
    }
    
    const [participantes] = await pool.query(
      `SELECT p.*, u.nombre_completo, u.username
       FROM PARTICIPANTES_VIDEOLLAMADA p
       INNER JOIN USUARIO u ON p.id_usuario = u.id_usuario
       WHERE p.id_sesion = ?`,
      [id]
    );
    
    res.json({
      ...videollamada[0],
      participantes
    });
  } catch (error) {
    console.error('Error al obtener videollamada:', error);
    res.status(500).json({ error: 'Error al obtener videollamada' });
  }
});

app.post('/api/videollamadas', authenticateToken, async (req, res) => {
  let connection;
  
  try {
    const { titulo, descripcion, participantes } = req.body;
    
    console.log('Creando videollamada:', { titulo, participantes });
    
    if (!titulo || !participantes || participantes.length === 0) {
      return res.status(400).json({ 
        error: 'Título y participantes son obligatorios' 
      });
    }
    
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    const codigoSala = `TamizajeVisual-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const linkJitsi = `https://meet.jit.si/${codigoSala}`;
    
    console.log('Link generado:', linkJitsi);
    

    const [result] = await connection.query(
      `INSERT INTO SESION_VIDEOLLAMADA 
       (titulo, descripcion, link_meet, creada_por, estado, fecha_inicio)
       VALUES (?, ?, ?, ?, 'activa', NOW())`,
      [titulo, descripcion, linkJitsi, req.user.id]
    );
    
    const idSesion = result.insertId;
    console.log('Videollamada creada con ID:', idSesion);
    
    for (const idParticipante of participantes) {
      await connection.query(
        `INSERT INTO PARTICIPANTES_VIDEOLLAMADA (id_sesion, id_usuario)
         VALUES (?, ?)`,
        [idSesion, idParticipante]
      );
    }
    
    await connection.query(
      `INSERT INTO AUDITORIA 
       (id_usuario, accion, tabla_afectada, id_registro_afectado, descripcion)
       VALUES (?, 'videollamada', 'SESION_VIDEOLLAMADA', ?, ?)`,
      [req.user.id, idSesion, `Videollamada creada: ${titulo}`]
    );
    
    await connection.commit();
    
    const [videollamadaCreada] = await connection.query(
      `SELECT v.*, u.nombre_completo as creador_nombre
       FROM SESION_VIDEOLLAMADA v
       INNER JOIN USUARIO u ON v.creada_por = u.id_usuario
       WHERE v.id_sesion = ?`,
      [idSesion]
    );
    
    console.log('Emitiendo notificaciones a participantes...');
    
    for (const idParticipante of participantes) {
      io.to(`user_${idParticipante}`).emit('nueva_videollamada', {
        id_sesion: idSesion,
        titulo: titulo,
        descripcion: descripcion,
        creador: req.user.username,
        participantes: participantes,
        link_meet: linkJitsi
      });
      console.log(`Notificación enviada a usuario ${idParticipante}`);
    }
    
    res.json({
      mensaje: 'Videollamada creada exitosamente',
      videollamada: {
        id_sesion: idSesion,
        ...videollamadaCreada[0]
      }
    });
    
  } catch (error) {
    if (connection) await connection.rollback();
    console.error('Error al crear videollamada:', error);
    res.status(500).json({ error: 'Error al crear videollamada: ' + error.message });
  } finally {
    if (connection) connection.release();
  }
});

app.post('/api/videollamadas/:id/unirse', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [videollamada] = await pool.query(
      'SELECT * FROM SESION_VIDEOLLAMADA WHERE id_sesion = ? AND estado = "activa"',
      [id]
    );
    
    if (videollamada.length === 0) {
      return res.status(404).json({ error: 'Videollamada no encontrada o ya finalizada' });
    }
    
    const [participante] = await pool.query(
      'SELECT * FROM PARTICIPANTES_VIDEOLLAMADA WHERE id_sesion = ? AND id_usuario = ?',
      [id, req.user.id]
    );
    
    if (participante.length > 0) {
      await pool.query(
        'UPDATE PARTICIPANTES_VIDEOLLAMADA SET unido_en = NOW() WHERE id_sesion = ? AND id_usuario = ?',
        [id, req.user.id]
      );
    } else {
      await pool.query(
        'INSERT INTO PARTICIPANTES_VIDEOLLAMADA (id_sesion, id_usuario, unido_en) VALUES (?, ?, NOW())',
        [id, req.user.id]
      );
    }
    
    io.to(`videollamada_${id}`).emit('usuario_unido', {
      id_sesion: id,
      usuario: req.user.username,
      id_usuario: req.user.id
    });
    
    res.json({ 
      mensaje: 'Te has unido a la videollamada',
      link_meet: videollamada[0].link_meet
    });
    
  } catch (error) {
    console.error('Error al unirse a videollamada:', error);
    res.status(500).json({ error: 'Error al unirse a videollamada' });
  }
});

app.post('/api/videollamadas/:id/salir', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    await pool.query(
      'UPDATE PARTICIPANTES_VIDEOLLAMADA SET salio_en = NOW() WHERE id_sesion = ? AND id_usuario = ? AND salio_en IS NULL',
      [id, req.user.id]
    );
    
    io.to(`videollamada_${id}`).emit('usuario_salio', {
      id_sesion: id,
      usuario: req.user.username,
      id_usuario: req.user.id
    });
    
    res.json({ mensaje: 'Has salido de la videollamada' });
    
  } catch (error) {
    console.error('Error al salir de videollamada:', error);
    res.status(500).json({ error: 'Error al salir de videollamada' });
  }
});

app.put('/api/videollamadas/:id/finalizar', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [videollamada] = await pool.query(
      'SELECT * FROM SESION_VIDEOLLAMADA WHERE id_sesion = ? AND creada_por = ?',
      [id, req.user.id]
    );
    
    if (videollamada.length === 0) {
      return res.status(403).json({ error: 'Solo el creador puede finalizar la videollamada' });
    }
    
    await pool.query(
      'UPDATE SESION_VIDEOLLAMADA SET estado = "finalizada", fecha_fin = NOW() WHERE id_sesion = ?',
      [id]
    );
    
    await pool.query(
      'UPDATE PARTICIPANTES_VIDEOLLAMADA SET salio_en = NOW() WHERE id_sesion = ? AND salio_en IS NULL',
      [id]
    );
    
    await pool.query(
      `INSERT INTO AUDITORIA 
       (id_usuario, accion, tabla_afectada, id_registro_afectado, descripcion)
       VALUES (?, 'videollamada', 'SESION_VIDEOLLAMADA', ?, 'Videollamada finalizada')`,
      [req.user.id, id]
    );
    
    const [participantes] = await pool.query(
      'SELECT id_usuario FROM PARTICIPANTES_VIDEOLLAMADA WHERE id_sesion = ?',
      [id]
    );
    
    participantes.forEach(p => {
      io.to(`user_${p.id_usuario}`).emit('videollamada_finalizada', {
        id_sesion: id
      });
    });
    
    res.json({ mensaje: 'Videollamada finalizada correctamente' });
    
  } catch (error) {
    console.error('Error al finalizar videollamada:', error);
    res.status(500).json({ error: 'Error al finalizar videollamada' });
  }
});


const PORT = process.env.PORT || 3001;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`
════════════════════════════════════════════════
  🚀 SERVIDOR DESPLEGADO EN RENDER.COM
  Puerto: ${PORT}
  Entorno: ${process.env.NODE_ENV || 'development'}
  Base de datos: ${process.env.DB_NAME}
════════════════════════════════════════════════
  `);
});