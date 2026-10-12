# LEARN — Detection Validation Lab (à lire en entier avant un entretien)

## 1. Le projet en une minute (pitch oral)

« J'ai écrit 8 détections Windows en Sigma, mappées MITRE ATT&CK v19, et je les teste
comme SigmaHQ teste ses propres règles : sur de **vrais journaux**. Trois contrôles en CI.
Un : un runner Windows GitHub jetable avec Sysmon, une phase d'activité admin normale,
puis 8 tests Atomic Red Team standard et bénins ; chaque règle doit sonner sur son test
et rester muette sur la phase normale. Deux : les journaux réels d'un poste Windows 10
propre (342 000 événements Sysmon), pour mesurer le bruit. Trois : 204 enregistrements
d'attaques réels du dépôt SigmaHQ. Le moteur est Chainsaw, un outil d'IR. Mes règles v1
sonnaient 32 fois sur le poste propre, la v2 cinq fois, et chaque cas restant est accepté
avec une justification écrite. Le contrôle sur runner n'a pas encore tourné. »

## 2. Les mots à connaître

- **Sysmon** : service Microsoft (Sysinternals) qui écrit des événements détaillés dans
  le journal `Microsoft-Windows-Sysmon/Operational`. EID 1 = création de processus (avec
  la ligne de commande et le parent), EID 13 = écriture d'une valeur de registre.
- **EVTX** : le format binaire des journaux Windows (ce qu'on ouvre dans l'Observateur
  d'événements). `wevtutil epl` exporte un journal en `.evtx`.
- **Sigma** : format YAML de règles de détection, indépendant du SIEM. `logsource` dit
  quel journal, `detection` contient des sélections et une `condition`. Modificateurs :
  `|contains`, `|endswith`, `|startswith`, `|re` (expression régulière), `|all`.
- **Corrélation Sigma** (v2) : règle qui compte des résultats d'autres règles.
  `value_count` = nombre de **valeurs distinctes** d'un champ dans une fenêtre de temps,
  par groupe (`group-by`).
- **Building block** : règle qui enregistre un fait sans lever d'alerte (ici dvl_004,
  niveau `informational`) ; une autre règle l'utilise (dvl_005). Idée reprise d'Elastic.
- **Chainsaw** : outil de WithSecure qui lit des EVTX et applique des règles Sigma via
  un fichier de *mapping* (quel événement Windows correspond à quel `logsource`).
- **Atomic Red Team** : bibliothèque de Red Canary de petits tests, un YAML par
  technique ATT&CK, chacun avec un GUID et une commande de nettoyage.
  **Invoke-AtomicRedTeam** est le module PowerShell qui les exécute.
- **Goodlog / baseline** : journaux d'une machine propre. Toute alerte dessus est un
  faux positif. SigmaHQ utilise la baseline de Nextron Systems.
- **Faux positif (FP) / faux négatif (FN)** : alerte sur du légitime / pas d'alerte sur
  une vraie attaque.
- **Allow-list** (liste d'exceptions) : FP acceptés pour **un** environnement, avec une
  raison, sans affaiblir la règle partagée.
- **Mutation** : on casse volontairement une règle pour vérifier que les tests échouent.
  Si rien n'échoue, les tests ne protègent rien.
- **ATT&CK v19** : depuis avril 2026, la tactique « Defense Evasion » s'appelle
  **Stealth** (TA0005) et une tactique **Defense Impairment** (TA0112) est apparue.

## 3. Comment ça marche, étape par étape

1. **Règles** (`rules/`). 7 règles Sigma simples + 1 corrélation. Clé courte = nom de
   fichier (`dvl_001`), Chainsaw renvoie l'UUID ; `dvl/rules.py` fait le lien.
2. **Chasse** (`dvl/chainsaw.py`). `chainsaw hunt <evtx> --sigma rules/sigma --mapping
   sigma-event-logs-all.yml --json`. On garde pour chaque résultat : règle, heure UTC,
   machine, EventID, champs de l'événement (`dvl/hits.py`).
3. **Corrélation** (`dvl/correlate.py`). Chainsaw ne sait pas exécuter les corrélations
   Sigma, donc je le fais en Python **en lisant les paramètres dans le YAML** de dvl_005
   (seuil 3, fenêtre 5 min, groupe = machine + `ParentProcessGuid`, champ compté =
   `CommandLine`). Fenêtre glissante ; après une alerte, le comptage repart à zéro.
4. **Contrôle 1 — télémétrie** (CI uniquement). Sur le runner : installation de Sysmon
   (config SwiftOnSecurity épinglée + SHA-256), audit « User Account Management »,
   phase bénigne avec des *quasi-attaques* (`-Encoding ascii`, `schtasks /query`,
   `reg query ...\Run`, 2 commandes de recon seulement), puis les 8 tests Atomic. Le
   harnais note l'heure UTC de début/fin de chaque phase (`manifest.json`). Un résultat
   compte pour un test seulement dans sa fenêtre (−1 s / +5 s). Le nettoyage tourne 7 s
   après la fenêtre. Échec si : une règle attendue ne sonne pas, ou une règle d'alerte
   sonne dans la phase bénigne.
5. **Contrôle 2 — goodlog**. Chainsaw sur la baseline Windows 10 ; chaque alerte doit
   correspondre à une entrée de `lab/known_fps.yaml` (toutes ses conditions vraies, avec
   un nombre max). Une entrée qui ne sert plus est signalée « stale ».
6. **Contrôle 3 — échantillons**. Fichiers EVTX réels avec la liste des règles qui
   doivent sonner ; toute autre alerte échoue.
7. **Auto-test du contrôle 1** : la CI casse dvl_006 (`mshta.exe` → `mshta_MUTANT.exe`)
   et vérifie que le contrôle passe au rouge (code 1).

## 4. L'histoire du tuning (à raconter, c'est le cœur de l'entretien)

Sur le poste Windows 10 propre, la v1 a levé **32 alertes** :
- 16 « clé Run » : installeurs (Opera, Zoom, iTunes, Google Drive, .NET…). Leçon : ne
  pas filtrer sur **qui écrit** (un installeur dans %TEMP% ressemble à un malware), mais
  sur **ce qui sera lancé** : une cible sous `Program Files` demande des droits admin.
- 11 « schtasks /create » : 10 d'Office Click-to-Run (parent sous `Program Files`).
- 3 « compte créé » : `defaultuser0`, `WDAGUtilityAccount`, et le premier compte (OOBE).
- 2 « PowerShell encodé » : en fait `-Encoding ascii`. ` -en` est un préfixe de
  `-EncodedCommand` **et** de `-Encoding`. D'où la regex qui exige un blob base64.

v2 : **5 alertes**, chacune acceptée dans l'allow-list avec sa raison (Spotify, nettoyage
OneDrive, `grpconv -o`, tâche K-Lite, compte OOBE). Chaque filtre est aussi un **angle
mort**, écrit dans `docs/TUNING.md`.

## 5. Questions d'entretien (avec réponses)

**Q1. Qu'est-ce qui est réel dans ce projet ?**
Les journaux : runner Windows avec Sysmon, baseline Windows 10 de Nextron, enregistrements
SigmaHQ. Les outils : Chainsaw, Sysmon, Atomic Red Team. Aucune ligne de journal n'est
écrite par moi. Ce qui n'est pas réel : pas de SIEM, pas d'AD, pas de vrai attaquant.

**Q2. Le contrôle 1 a-t-il tourné ?**
Pas encore au moment où j'écris : il ne tourne que dans GitHub Actions. Je donnerai les
résultats du premier run, y compris ce qui casse. *(À mettre à jour après le premier run.)*

**Q3. Pourquoi ne pas lancer les tests Atomic sur ton PC ?**
Ils installent Sysmon, changent la politique d'audit, créent un compte et une tâche.
Un runner GitHub est une VM jetable détruite après le job : c'est l'isolation la plus
simple et gratuite. Et on ne lance jamais ce type de test sur une machine de l'école ou
d'un employeur sans autorisation écrite.

**Q4. Les tests Atomic sont-ils dangereux ?**
Ceux-là non : affichage de texte, découverte, tâche/clé Run/compte créés puis supprimés.
J'ai exclu par un test les familles vol d'identifiants, impact, désactivation de
défenses, effacement de journaux, téléchargement, mouvement latéral.

**Q5. Pourquoi Chainsaw et pas Wazuh ou Splunk ?**
Chainsaw lit directement des EVTX avec des règles Sigma, tourne en CI sur Linux et
Windows en quelques secondes, sans serveur. Dans un SOC, je convertirais les mêmes
règles avec un backend pySigma (SPL, KQL) ; Wazuh, je l'ai pratiqué dans soc-detection-lab.

**Q6. Explique dvl_001.**
Image `powershell.exe`/`pwsh.exe` (ou `OriginalFileName`, pour résister au renommage)
**et** regex `\s[-/]e(c|n[a-z]*)?\s+["']?[A-Za-z0-9+/=]{20,}` : un tiret ou slash, `e`
seul, `ec`, ou `en…` (tous les préfixes de `-EncodedCommand`), puis au moins 20
caractères base64. Ça évite `-Encoding ascii` et `-ExecutionPolicy Bypass`.

**Q7. Que rate dvl_001 ?**
Un script qui décode lui-même (`[Convert]::FromBase64String`), `-e $variable`, un autre
interpréteur. Et elle peut sonner sur une chaîne qui ressemble à `-e <base64>` dans un
texte. Le journal PowerShell 4104 (Script Block Logging) verrait le contenu décodé.

**Q8. Pourquoi dvl_004 n'est pas une alerte ?**
`whoami` seul est normal : un admin, un script de connexion. Il apparaît même dans la
baseline propre. L'alerte est la **corrélation** : 3 commandes de recon différentes du
même parent en 5 minutes (dvl_005), ce qui ressemble à quelqu'un qui découvre la machine.

**Q9. Pourquoi grouper par `ParentProcessGuid` ?**
Le GUID Sysmon identifie une instance de processus de façon unique (le PID est réutilisé).
Même shell = même session de commandes. Limite : un attaquant qui ouvre un shell par
commande n'est pas regroupé ; grouper par utilisateur serait l'étape suivante.

**Q10. Pourquoi deux règles pour T1136.001 ?**
dvl_008 voit la commande `net user /add` dans Sysmon ; dvl_007 voit le résultat (4720)
dans le journal Security. Si une source manque, l'autre sonne. Et `[ADSI]` ou
`New-LocalUser` échappent à dvl_008 mais pas à dvl_007 si l'audit est actif.

**Q11. Comment distingues-tu un filtre de règle d'une entrée d'allow-list ?**
Filtre = vrai partout (comptes intégrés, cible sous Program Files) → il change la règle,
il est dans Git. Allow-list = vrai pour cette machine (Spotify, K-Lite) → la règle reste
générique, l'exception a une raison, toutes ses conditions doivent être vraies, et elle
est signalée si elle ne sert plus.

**Q12. Ton taux de faux positifs ?**
Je ne donne pas de taux. J'ai un chiffre précis : 5 alertes sur une machine Windows 10
propre (342 116 événements Sysmon), toutes expliquées. Pour un taux, il faudrait un parc
de machines sur plusieurs semaines, et une mesure par règle et par jour.

**Q13. Quel est le risque de tes filtres ?**
Chaque filtre est un angle mort : une valeur Run qui pointe vers un binaire sous Program
Files avec des arguments malveillants, une tâche créée par un updater compromis, un
compte nommé `defaultuser0`. Je les ai écrits dans TUNING.md pour qu'on puisse les chasser.

**Q14. Comment sais-tu que tes tests servent à quelque chose ?**
Mutations : supprimer la branche WMIC, exiger 2 000 caractères base64, faire matcher
n'importe quel verbe `schtasks` → les tests échouent. En CI, la règle mshta cassée doit
faire échouer le contrôle 1.

**Q15. Pourquoi des fenêtres de temps et pas un journal par test ?**
Vider les journaux entre deux tests créerait des événements 1102/104 et ferait perdre
des données. Les fenêtres (heure UTC prise sur la même horloge que Sysmon) suffisent ;
le nettoyage est placé hors fenêtre et une pause sépare les tests.

**Q16. Qu'est-ce qu'un mapping Chainsaw ?**
Le fichier qui dit qu'un `logsource: category: process_creation` correspond à Sysmon EID 1
(ou Security 4688), `registry_set` à Sysmon EID 13, `service: security` au fournisseur
Security-Auditing. Sans lui, Chainsaw ne sait pas sur quels événements appliquer la règle.

**Q17. Un piège que tu as rencontré ?**
Chainsaw ignore **sans erreur claire** une règle sans `description` ou `date` : il dit
seulement « No valid detection rules ». J'ai ajouté un test qui chasse avec chaque règle
seule, pour qu'une règle ignorée casse le build.

**Q18. Pourquoi le SHA-256 et les commits épinglés ?**
Reproductibilité et chaîne d'approvisionnement : la même version de Chainsaw, de la
config Sysmon, des tests Atomic et des données à chaque run. Un fichier modifié en amont
fait échouer le téléchargement au lieu de changer le résultat en silence.

**Q19. Quelle est la différence avec soc-detection-lab ?**
soc-detection-lab : règles Wazuh rejouées dans `wazuh-logtest`, sur des lignes que j'ai
écrites. Ici : endpoint Windows réel, Sysmon réel, bruit mesuré sur une vraie machine.
Les deux ensemble : écrire une règle, la tester sur une vraie attaque, mesurer son bruit.

**Q20. Qu'est-ce que tu ferais ensuite ?**
Faire tourner la CI et documenter les runs ; ajouter la baseline Windows 11 ; convertir
les règles en KQL/SPL avec pySigma ; ajouter le Script Block Logging 4104 ; envoyer les
EVTX du runner dans le Wazuh de soc-detection-lab.

## 6. Ce que Mohamed doit faire lui-même avant d'en parler

1. Relancer `python scripts/get_chainsaw.py` puis `python -m pytest` (92 tests) et les
   contrôles 2 et 3 sur son PC (commandes du README).
2. Pousser le dépôt, lancer le workflow, **lire chaque échec** et le corriger ; noter
   l'historique des runs dans le README (comme soc-detection-lab).
3. Télécharger l'artefact `real-telemetry`, ouvrir les EVTX dans l'Observateur
   d'événements, retrouver l'événement Sysmon EID 1 du test A1 et l'EID 13 du test A3.
4. Savoir expliquer sans notes : la regex de dvl_001, la corrélation dvl_005, chaque
   ligne de `known_fps.yaml`, les 3 angles morts de TUNING.md.
5. Ne jamais lancer `lab/ci/*.ps1` sur son PC ni sur une machine qui ne lui appartient pas.

## 7. Lignes de CV (§7 du DIRECTOR-AUDIT : max 3 lignes, chiffres vrais, une réserve)

**FR — tant que la CI n'a pas tourné :**
- **Detection Validation Lab** (Sigma, Sysmon, Chainsaw, Python, GitHub Actions) : 8 détections Windows mappées ATT&CK v19, testées sur journaux réels : bruit ramené de 32 à 5 alertes justifiées sur une baseline Windows 10 propre (342 000 événements Sysmon), 0 alerte inattendue sur 204 enregistrements d'attaque SigmaHQ. 92 tests. 8/8 tests Atomic Red Team détectés sur un runner Windows Server 2025 + Sysmon en CI, 0 faux positif en phase bénigne.

**EN — until the CI has run:**
- **Detection Validation Lab** (Sigma, Sysmon, Chainsaw, Python, GitHub Actions): 8 ATT&CK v19 Windows detections tested on real logs: noise cut from 32 to 5 justified alerts on a clean Windows 10 baseline (342k Sysmon events), 0 unexpected alert on 204 SigmaHQ attack recordings. 92 tests. 8/8 Atomic Red Team tests detected on a Windows Server 2025 + Sysmon CI runner, 0 false positives in the benign phase.

*(Après un run vert : remplacer la dernière phrase par « validées en CI sur Sysmon réel avec 8 tests Atomic Red Team (N/8), régression volontaire = build rouge ». Mettre le vrai N.)*

**À ne jamais écrire :** « taux de faux positifs de X % », « détecte les attaquants »,
« 0 faux positif », « déployé dans un SOC », « validé en CI » avant le premier run vert,
« simulation d'attaque » sans dire « tests Atomic standard sur runner jetable ».
