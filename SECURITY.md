# Politique de sécurité

## Signaler une vulnérabilité

Ne publiez pas de faille dans une issue. Utilisez le signalement privé de GitHub :
**Security → Report a vulnerability** sur ce dépôt. Indiquez la version (`sbmgr --version`),
la plateforme concernée et, si possible, comment reproduire le problème sans mot de passe réel.

## Versions suivies

Seule la dernière version publiée est suivie. Le projet est en **alpha**.

## À savoir avant de l'utiliser

- **Rien n'a été validé sur matériel** avec cet outil. Essayez `-a status` puis `-a db_list`
  sur un serveur de test avant toute écriture, et `--dry-run` avant un import, une suppression
  ou un `reset_keys`.
- **La vérification TLS est désactivée par défaut** (les BMC ont presque toujours un certificat
  auto-signé). Sur un réseau de gestion non maîtrisé, une personne en position d'interception
  peut se faire passer pour un BMC et capter les identifiants. Utilisez `--ca-file` ou
  `--verify-tls`, et des comptes dédiés à Secure Boot.
- Le CSV d'entrée contient des mots de passe en clair : permissions `0600`, jamais versionné.
- `reset_keys` avec `DeleteAllKeys` ou `DeletePK` met le serveur en Setup Mode : le Secure
  Boot cesse de le protéger. L'outil exige `--confirm`.
- L'outil ne redémarre jamais un serveur : les changements restent en attente jusqu'au
  prochain démarrage.
