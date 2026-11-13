# Android Contacts pour Odoo 19

Module Odoo accompagnant l'application Android Laudhair Odoo. Après connexion web
et consentement, il délivre une clé limitée aux endpoints de lecture de contacts
du module, valable 90 jours. Les droits et règles Odoo de l'utilisateur restent
applicables. La clé peut être révoquée dans les préférences de sécurité Odoo.

Installer `odoo_android_contacts` dans le chemin des addons et activer le module
dans la base. La durée maximale de clé autorisée par les groupes de l'utilisateur
doit être d'au moins 90 jours : le module ne contourne pas cette politique.
Le serveur doit être accessible en HTTPS depuis le téléphone.

Le parcours d'autorisation utilise un code temporaire à usage unique et un
secret de vérification généré par l'application. La clé n'est pas placée dans
l'URL de redirection. Le module n'expose pas d'endpoint de modification des
contacts.

La déconnexion dans Android supprime sa copie locale de la clé et des contacts ;
pour invalider immédiatement la clé sur le serveur, la supprimer également dans
les préférences de sécurité Odoo.
