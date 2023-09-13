# **`Common Weakness Enumeration vs CERT coding standards`**

[CWE][1] es una lista de software y hardware desarrollada por una comunidad de tipo de vulnerabilidades. Sirve como un lenguaje en comun, una herramienta para medir la seguridad y una base para la identificacion de vulnerabilidades, mitigacion y prevencion.

[CERT coding standards][2] Es el conjunto de herramientas, practicas y metodos que se ha creado para identificar y prevenir fallas de seguridad durante el desarrollo temprano de sistemas de software, cuando es mas costeable.

*Similitudes entre CWE y CERT*

- Se enfocan en la prevencion de las vulnerabilidades de software
- Se basan en las mejores practicas de seguridad
- Se pueden utilizar para desarrollar codigo mas seguro

*Estandares de CERT que corresponden a CWE*

[CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer][3] 

Ciertos lenguajes permiten el direccionamiento directo de posiciones de memoria y no aseguran automáticamente que estas posiciones sean válidas para el buffer de memoria al que se está haciendo referencia. Esto puede provocar que se realicen operaciones de lectura o escritura en ubicaciones de memoria que pueden estar asociadas a otras variables, estructuras de datos o datos internos del programa.

Como resultado, un atacante puede ser capaz de ejecutar código arbitrario, alterar el flujo de control previsto, leer información sensible, o hacer que el sistema se bloquee.


Ejemplo

Este ejemplo aplica un procedimiento de codificacion a una cadena de entrada y la almacena en un buffer.

```
char * copy_input(char *user_supplied_string){
    int i, dst_index;
    char *dst_buf = (char*)malloc(4*sizeof(char) * MAX_SIZE);
    if ( MAX_SIZE <= strlen(user_supplied_string) ){
        die("user string too long, die evil hacker!");
    }
    dst_index = 0;
    for ( i = 0; i < strlen(user_supplied_string); i++ ){
        if( '&' == user_supplied_string[i] ){
            dst_buf[dst_index++] = '&';
            dst_buf[dst_index++] = 'a';
            dst_buf[dst_index++] = 'm';
            dst_buf[dst_index++] = 'p';
            dst_buf[dst_index++] = ';';
        }
        else if ('<' == user_supplied_string[i] ){
            /* encode to &lt; */
        }
        else dst_buf[dst_index++] = user_supplied_string[i];
    }
    return dst_buf;
}
```
El programador intenta codificar el caracter & en la cadena controlada por el usuario, sin embargo, la longitud de la cadena se valida antes de aplicar el procedimiento de codificacion. Ademas, el programador asume que la expansion de la codificacion solo expandira un caracter dado por un factor de 4, mientras que la codificacion del & expande por 5. Como resulado, cuando el procedimiento de codificacion expande la cadena es posible desbordar el buffer del destino si el atacante proporciona una cadena con muchos &s.

[CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')][4]

Esta vulnerabilidad permite a los atacantes ejecutcar comandos inesperados y peligrosos en el sistema operativo. Esta vulnerabilidad puede ser explotada en entornos en los que el atacante no tiene acceso directo al sistema operativo, como aplicaciones web. Puede ejecutar comando con privilegios si este accede a un sistema privilegiado. 

Ejemplo

El siguiente codigo acepta un nombre de archivo como argumento de linea de comandos y muestra el contenido del archivo al usuario. El programa se instala como setuid root por que esta pensado como herramienta de aprendizaje para permitir a los administradores del sistema inspeccionar archivos privilegiados del sistema sin darles la capacidad de modificarlos o dañar el sistema.

```
int main(int argc, char** argv) {
    char cmd[CMD_MAX] = "/usr/bin/cat ";
    strcat(cmd, argv[1]);
    system(cmd);
}
```
Dado que el programa se ejecuta con privilegios de root, la llamada a system() tambien se ejecuta con privilegios root. Si un usuario especifica un nombre de archivo estandar, la llamada funciona como se espera. Sin embargo, si un atacante pasa una cadena de la forma ";rm -rf/", entonces la llamada a system() falla al ejecutar el cat debido a la falta de argumentos y entonces se lanza a borrar recursivamente el contenido de particion raiz.


[CWE-200: Exposure of Sensitive Information to an Unauthorized Actor][5]

Hay diferentes tipos de errores que pueden provocar la exposicion de informacion. La gravedad del error puede variar, dependiendo del contexto en el que opere el producto, el tipo de informacion sensible que se revele y los beneficios que puede proporcionar un atacante.

Ejemplo

En el ejemplo, el metodo getUserBankAccount recupera un objeto de cuenta bancaria de una base de datos utilizando el nombre de usuario y el numero de cuenta consultados en una base de datos. Si se produce un SQLException al consultar la base de datos, se crea un error y se envia a un archivo de registro.

```
public BankAccount getUserBankAccount(String username, String accountNumber) {
    BankAccount userAccount = null;
    String query = null;
    try {
        if (isAuthorizedUser(username)) {
            query = "SELECT * FROM accounts WHERE owner = "
            + username + " AND accountID = " + accountNumber;
            DatabaseManager dbManager = new DatabaseManager();
            Connection conn = dbManager.getConnection();
            Statement stmt = conn.createStatement();
            ResultSet queryResult = stmt.executeQuery(query);
            userAccount = (BankAccount)queryResult.getObject(accountNumber);
        }
    } catch (SQLException ex) {
        String logMessage = "Unable to retrieve account information from database,\nquery: " + query;
        Logger.getLogger(BankManager.class.getName()).log(Level.SEVERE,logMessage, ex);
    }
    return userAccount;
}
```

El mensaje de error que se crea incluye informacion sobre la consulta a la base de datos que puede contener informacion sensible sobre la base de datos o la logica de la consulta. En este caso, el mensaje de error expondra el nombre de la tabla y los nombres de las columnas utilizadas en la base de datos. Estos datos podrian utilizarse para simplificar otros ataques como SQL Injection para acceder directamente a la base de datos.

# References 
[Common Weakness Enumeration][1]

[CERT coding standards][2]

[CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer][3]

[CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')][4]

[CWE-200: Exposure of Sensitive Information to an Unauthorized Actor][5]

[1]: https://cwe.mitre.org/
[2]: https://www.cert.org/secure-coding
[3]: https://cwe.mitre.org/data/definitions/119.html
[4]: https://cwe.mitre.org/data/definitions/78.html
[5]: https://cwe.mitre.org/data/definitions/200.html
