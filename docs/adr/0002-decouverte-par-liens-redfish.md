# 0002 — Découverte par liens Redfish, pas d'URI en dur

- Statut : accepté
- Date : 2026-10-05

## Contexte

Le script Python code en dur `System.Embedded.1`, `Bios/Settings` et le chemin OEM
`SecureBoot/Oem/Dell/Certificates/DB`. Le changelog en montre le coût : le suivi de
tâche cassait (404) parce que le chemin `TaskMonitors/` était supposé alors que le
firmware renvoyait `Tasks/`. La spec DMTF DSP0266 1.14 interdit ces suppositions :
« Clients shall not make assumptions about the URIs for the members of a resource
collection ». Les OpenAPI Dell iDRAC9 et iDRAC10 utilisent `{ComputerSystemId}`.

## Décision

Tout part de `/redfish/v1/` et suit les `@odata.id` : `Links.Sessions`, `Systems` (le
membre est découvert), `SecureBoot`, `Bios` et son lien `@Redfish.Settings`. Le
`Location` d'une réponse 202 est suivi tel quel et traité comme opaque. Les résolutions
sont mises en cache par hôte. Un chemin en dur n'est qu'un repli, jamais le chemin nominal.

## Conséquences

- Robuste aux changements de firmware et à iDRAC10 (identifiant de système non figé).
- Une requête de découverte supplémentaire par hôte au démarrage.
- Un BMC qui ne publie pas un lien attendu produit une erreur explicite, pas un 404 obscur.
- Les tests du faux BMC doivent exposer ces liens (fixtures complètes depuis la racine).
