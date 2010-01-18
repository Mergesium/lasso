============================
Implantation du mapping Java
============================

:author: Benjamin Poussin <poussin@codelutin.com>

La m�me hierarchie d'objet � �t� faite dans la mesure du possible entre
l'implantation C et Java.

Conservation de l'objet C associ� � l'objet Java
================================================

Chaque objet Java h�rite d'un objet LassoNode qui contient un champs
*long c_lasso_object* qui permet de stocker la r�f�rence du pointer de
l'objet C associ� � cet objet Java.

Destruction des objets
======================

L'objet LassoNode contient aussi une m�thode finalize qui permet l'appel au
destructeur de l'objet C, lorsque l'objet java est lib�r�.

Si une m�thode destroy particuli�re doit-�tre utilis� pour un objet C, il
suffit dans l'objet Java de red�finir la m�thode
*native protected void destroy();* et de l'implanter diff�rement dans
l'implantation C de la m�thode native.

Acces au attribut des objets C
==============================

Chaque attribut des objets C est accessible par une m�thode d'acces. Cette
m�thode se charge de demander la construction de l'objet de repr�sentation
Java du champs. Ceci est fait par une m�thode *init<FieldName>Field*. Cette
m�thode ne modifie l'attribut que si l'objet C et l'objet Java ne sont plus
synchronis�, c'est � dire si la valeur dans l'objet C � �t� modifi� ou que
l'objet Java la repr�sentant n'a jamais �t� cr�er.

