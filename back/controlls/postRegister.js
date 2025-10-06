import conexion from "../bd.js";  // Importa la conexión a la base de datos
import bcrypt from "bcrypt";      // Importa bcrypt para hashear contraseñas

export default async function postRegister(req, res) {
  try {
    // 🔹 Obtener los datos enviados por el cliente
    const { nombre, apellido, email, password, repetirPassword, telefono } = req.body;

    // 🔹 Validar que los campos obligatorios estén presentes
    if (!nombre || !apellido || !email || !password || !repetirPassword) {
      return res.status(400).json({ mensaje: "Faltan datos obligatorios." });
    }

    // 🔹 Validar que nombre y apellido solo tengan letras y espacios
    const soloLetras = /^[A-Za-zÁÉÍÓÚáéíóúÑñ\s]+$/;
    if (!soloLetras.test(nombre) || !soloLetras.test(apellido)) {
      return res.status(400).json({ mensaje: "El nombre y apellido solo pueden contener letras y espacios." });
    }

    // 🔹 Validar longitud mínima de nombre y apellido
    if (nombre.length < 2 || apellido.length < 2) {
      return res.status(400).json({ mensaje: "El nombre y apellido deben tener al menos 2 caracteres." });
    }

    // 🔹 Validar formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ mensaje: "El formato del correo electrónico no es válido." });
    }

    // 🔹 Validar contraseña: mínimo 6 caracteres, debe contener letras y números
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*()_+\-={}\[\]|:;"'<>,.?/~`]{6,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        mensaje: "La contraseña debe tener al menos 6 caracteres e incluir letras y números."
      });
    }

    // 🔹 Validar que las contraseñas coincidan
    if (password !== repetirPassword) {
      return res.status(400).json({ mensaje: "Las contraseñas no coinciden." });
    }

    // 🔹 Validar teléfono si se envía
    if (telefono && !/^[0-9+\-\s]{6,20}$/.test(telefono)) {
      return res.status(400).json({ mensaje: "El teléfono contiene caracteres no válidos." });
    }

    // 🔹 Verificar si el usuario ya existe en la base de datos
    try {
      const [existeUsuario] = await conexion.query(
        "SELECT * FROM usuarios WHERE email = ?",
        [email.trim().toLowerCase()]
      );
      if (existeUsuario.length > 0) {
        return res.status(409).json({ mensaje: "El usuario ya está registrado." });
      }
    } catch (err) {
      console.error("Error al verificar usuario:", err);
      return res.status(500).json({ mensaje: "Error al verificar el usuario." });
    }

    // 🔹 Hashear la contraseña antes de guardarla
    let hash;
    try {
      const saltRounds = 10;
      hash = await bcrypt.hash(password, saltRounds);
    } catch (err) {
      console.error("Error al hashear contraseña:", err);
      return res.status(500).json({ mensaje: "Error al procesar la contraseña." });
    }

    // 🔹 Insertar el nuevo usuario en la base de datos
    try {
      const [resultado] = await conexion.query(
        "INSERT INTO usuarios (nombre, apellido, email, password, telefono) VALUES (?, ?, ?, ?, ?)",
        [nombre.trim(), apellido.trim(), email.trim().toLowerCase(), hash, telefono || null]
      );

      // 🔹 Hashear ID del usuario e "id" para crear la cookie segura
      const hashedId = await bcrypt.hash(resultado.insertId.toString(), 10);
      const hashedCookieName = await bcrypt.hash("id", 10);

      // 🔹 Configuración de la cookie según el entorno
      const inProduction = process.env.NODE_ENV === 'production';
      res.cookie(hashedCookieName, hashedId, {
        httpOnly: true, 
        secure: inProduction,
        sameSite: inProduction ? 'strict' : 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 1 día
      });

      // 🔹 Devolver mensaje de éxito
      return res.status(201).json({ mensaje: "Usuario registrado exitosamente." });

    } catch (err) {
      console.error("Error al insertar usuario:", err);
      return res.status(500).json({ mensaje: "Error al guardar el usuario." });
    }

  } catch (error) {
    // 🔹 Captura de errores inesperados
    console.error("Error general en postRegister:", error);
    return res.status(500).json({ mensaje: "Error interno del servidor." });
  }
}
