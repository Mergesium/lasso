================
JNI for dummy :)
================

Sous Linux le nom de la librairie compil�e doit obligatoirement commencer par **lib** et
finir par **.so**.

Pour charger � l'�x�cution la librairie elle doit-�tre dans le
LD_LIBRAIRY_PATH et en Java il faut la charger avec **System.loadLibrary**::

Par exemple si vous avec g�n�r� la librairie libjlasso.so, on la chargera
avec::

  System.loadLibrary("jlasso");

Pour connaitre le nom de la librairie que le syst�me attend, on peut
utiliser::

  System.out.println(System.mapLibraryName("jlasso"));

Comment ajouter des fonctions JNI
=================================

:ref: http://java.sun.com/docs/books/jni/html/jniTOC.html
:ref: http://gbm.esil.univ-mrs.fr/~tourai/Java/node48.html

Il faut cr�er les classes Java, et marquer les m�thodes qui doivent �tre
�crite en C, avec le mot cle native. Ces m�thodes n'ont pas de corps en
Java.

Il faut ensuite ex�cuter le Makefile se trouvant dans lasso/java pour qu'il
g�n�re les fichiers d'ent�te JNI. 

Il ne reste plus qu'a reprendre la signature de la m�thode et de la coder
dans le .c

