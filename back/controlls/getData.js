import conexion from "../bd.js"; // Importa la conexión a la base de datos
import bcrypt from "bcrypt"; // Importa bcrypt para comparar hashes

export default async function getData(req, res) {
  try {
    // 🔹 Obtener todas las cookies enviadas por el cliente
    const cookies = req.cookies;

    // 🔹 Si no hay cookies, denegar acceso
    if (!cookies || Object.keys(cookies).length === 0) {
      return res
        .status(401)
        .json({ mensaje: "No hay cookies, acceso denegado." });
    }

    let usuarioId = null; // Aquí guardaremos el ID del usuario si la cookie es válida

    // 🔹 Iterar sobre todas las cookies para encontrar la que corresponde al usuario
    for (const nombreCookie in cookies) {
      // 🔹 Comparar el nombre de la cookie con la cadena "id" hasheada
      const esMatch = await bcrypt.compare("id", nombreCookie);

      if (esMatch) {
        // 🔹 Si el nombre coincide, traemos todos los IDs de usuarios de la DB
        const [usuarios] = await conexion.query("SELECT id FROM usuarios");

        // 🔹 Iteramos sobre los usuarios y comparamos el valor de la cookie con su ID hasheado
        for (const u of usuarios) {
          const idMatch = await bcrypt.compare(
            u.id.toString(),
            cookies[nombreCookie]
          );
          if (idMatch) {
            usuarioId = u.id; // Guardamos el ID del usuario válido
            break; // Salimos del loop si encontramos coincidencia
          }
        }
        break; // Salimos del loop de cookies una vez que encontramos la cookie correcta
      }
    }

    // 🔹 Si no encontramos un usuario válido, denegamos el acceso
    if (!usuarioId) {
      return res
        .status(401)
        .json({ mensaje: "Cookie inválida o usuario no encontrado." });
    }

    // 🔹 Consultar los datos del usuario usando el ID encontrado
    const [resultado] = await conexion.query(
      "SELECT email, nombre, apellido, telefono, fecha_creacion FROM usuarios WHERE id = ?",
      [usuarioId]
    );

    // 🔹 Si no se encuentra el usuario en la base de datos, devolver error
    if (resultado.length === 0) {
      return res.status(404).json({ mensaje: "Usuario no encontrado." });
    }

    // 🔹 Si todo está correcto, devolver los datos del usuario
    return res.status(200).json({ usuario: resultado[0] });
  } catch (error) {
    // 🔹 Capturar cualquier error inesperado y devolver 500
    console.error("Error en getData:", error);
    return res.status(500).json({ mensaje: "Error interno del servidor." });
  }
}
