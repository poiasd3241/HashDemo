# HashDemo

Задача 3 (любая ОС)
Дан файл, содержащий имена файлов, алгоритм хэширования (один из MD5/SHA1/SHA256) и
соответствующие им хэш-суммы, вычисленные по соответствующему алгоритму и указанные в
файле через пробел. Напишите программу, читающую данный файл и проверяющую
целостность файлов.

Пример:

Файл сумм:
<p>file_01.bin md5 aaeab83fcc93cd3ab003fa8bfd8d8906</p>
<p>file_02.bin md5 6dc2d05c8374293fe20bc4c22c236e2e</p>
<p>file_03.bin md5 6dc2d05c8374293fe20bc4c22c236e2e</p>
<p>файл_04.txt sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709</p>

Пример вызова:
&lt;your program&gt; &lt;path to the input file&gt; &lt;path to the directory containing
the files to check&gt;

Формат вывода:
file_01.bin OK
file_02.bin FAIL
file_03.bin NOT FOUND
файл_04.txt OK
