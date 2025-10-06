import mysql from "mysql2/promise";

const conexion = await mysql.createConnection({
  host: "localhost",
  user: "root",        
  password: "",         
  database: "rn1",
});

export default conexion;
