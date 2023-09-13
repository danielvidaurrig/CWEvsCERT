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

Este ejemplo aplica un procedimiento de codificacion a una cadena de entrada y la almacena en un bufer.

```

```



# References 
[Common Weakness Enumeration][1]

[CERT coding standards][2]

[CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer][3]

[1]: https://cwe.mitre.org/
[2]: https://www.cert.org/secure-coding
[3]: https://cwe.mitre.org/data/definitions/119.html
