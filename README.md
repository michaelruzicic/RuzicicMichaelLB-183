# Schwachstellen in Appilkationen: Von der Erkennung zur Absicherung

## Introduktion

In der heutigen digitalisierten Welt, in der Anwendungen das Rückgrat zahlreicher Geschäftsprozesse bilden, ist die Sicherheit dieser Anwendungen entscheidender denn je. Das Ziel dieses ePortfolios ist es, meine tiefe Auseinandersetzung mit den Kernaspekten der Applikationssicherheit zu dokumentieren, ein Feld, das ständig im Wandel ist und stets neue Herausforderungen mit sich bringt. Im Rahmen des [Moduls 183](https://www.modulbaukasten.ch/module/183/3/de-DE?title=Applikationssicherheit-implementieren)habe ich mich intensiv mit fünf zentralen Handlungszielen beschäftigt:

| HZ | Handlungsziel                                                                                               |
|----|-------------------------------------------------------------------------------------------------------------|
| I  | Aktuelle Bedrohungen erkennen und erläutern können. Aktuelle Informationen zum Thema beschaffen und mögliche Auswirkungen aufzeigen und erklären können. |
| II  | Sicherheitslücken und ihre Ursachen in einer Applikation erkennen können. Gegenmassnahmen vorschlagen und implementieren können. |
| III  | Mechanismen für die Authentifizierung und Autorisierung umsetzen können.                                    |
| IV  | Sicherheitsrelevante Aspekte bei Entwurf, Implementierung und Inbetriebnahme berücksichtigen.               |
| V  | Informationen für Auditing und Logging generieren. Auswertungen und Alarme definieren und implementieren.   |

## Handlungsziel I
### Artefakt: OWASP Top Ten 2021 Tabelle

| Rang | Risiko                           | Beschreibung                                                                                       | Erkennungsmethoden                                                   | Gegenmaßnahmen                                                                           |
|------|----------------------------------|----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| 1    | Broken Access Control            | Unzureichende Einschränkung der Zugriffsrechte, die zu unbefugtem Zugriff führen kann.             | Überprüfung von Zugriffsprotokollen, Penetrationstests               | Implementierung von rollenbasierten Zugriffskontrollen, Prinzip der minimalen Rechte     |
| 2    | Cryptographic Failures           | Schwachstellen in der Verschlüsselung, die zur Offenlegung sensibler Daten führen können.          | Sicherheitsüberprüfungen der Kryptographie, Code-Reviews             | Verwendung sicherer und aktueller Kryptographiestandards, sichere Schlüsselverwaltung    |
| 3    | Injection                        | Einschleusen von bösartigem Code durch Eingabefelder, z.B. SQL, NoSQL, OS Command Injection.       | Eingabedatenvalidierung, Sicherheitsüberprüfungen                    | Verwendung von Prepared Statements und ORM-Frameworks, Validierung aller Eingaben        |
| 4    | Insecure Design                  | Mangel an Sicherheitsmaßnahmen im Design und Architektur der Software.                             | Threat Modelling, Architekturüberprüfungen                           | Anwendung von Secure-Design-Prinzipien, regelmäßige Sicherheitsaudits                    |
| 5    | Security Misconfiguration        | Fehlkonfigurationen, die zu Sicherheitslücken führen können, z.B. ungeschützte Datenbanken.        | Automatisierte Konfigurationsüberprüfungen, Sicherheitsaudits        | Strenge Konfigurationsmanagementprozesse, regelmäßige Updates und Patches                |
| 6    | Vulnerable and Outdated Components | Verwendung veralteter oder unsicherer Komponenten in der Software.                               | Softwarekompositionsanalyse, regelmäßige Abhängigkeitsüberprüfungen  | Aktualisierung auf die neuesten sicheren Versionen, Verwendung sicherer Bibliotheken     |
| 7    | Identification and Authentication Failures | Schwächen in der Identifikation und Authentifizierung, die zu unbefugtem Zugriff führen können. | Überprüfung der Authentifizierungsprotokolle, Penetrationstests      | Multi-Faktor-Authentifizierung, robuste Passwortrichtlinien                                |
| 8    | Software and Data Integrity Failures | Mangelnde Integritätsprüfungen, die zu unautorisierten Datenänderungen führen können.             | Integritätsüberprüfungen, Code-Signierung                            | Verwendung von Code-Signierung, Implementierung von Integritätsprüfungen                 |
| 9    | Security Logging and Monitoring Failures | Unzureichende Protokollierung und Überwachung, die das Erkennen von Sicherheitsvorfällen verhindert. | Überprüfung von Protokollen und Alarmen, Sicherheitsaudits          | Implementierung umfassender Protokollierungs- und Überwachungssysteme                    |
| 10   | Server-Side Request Forgery (SSRF) | Angriffe, bei denen der Server dazu gebracht wird, unerwünschte Aktionen auszuführen.               | Netzwerküberwachung, Sicherheitsüberprüfungen                        | Beschränkung ausgehender Anfragen, Verwendung sicherer Programmierpraktiken             |

**Nachweis der Zielerreichung:**
Die Tabelle zeigt meine Fähigkeit, komplexe Sicherheitsrisiken zu identifizieren und zu analysieren. Sie wurde eigenständig recherchiert und zusammengefasst, wodurch ich mein Wissen über Erkennungsmethoden und Gegenmaßnahmen vertiefen konnte.

**Erklärung des Artefakts:**
Die Tabelle bietet einen umfassenden Überblick über die zehn größten Sicherheitsrisiken im Bereich der Webanwendungssicherheit, einschließlich deren Beschreibung, Erkennungsmethoden und Gegenmaßnahmen. Sie dient als kompaktes Nachschlagewerk für die wichtigsten Bedrohungen und deren Abwehr.

**Kritische Beurteilung:**
Die OWASP Top Ten 2021 Tabelle erweist sich als ein effektives Instrument, um die zentralen Bedrohungen in der Applikationssicherheit abzubilden. Sie bietet eine solide Übersicht über kritische Sicherheitsrisiken. Da die Tabelle die Sicherheitsrisiken von 2021 abbildet, hätte eine Erweiterung mit Diskussionen über bestehende Angriffstrends und wie man ihnen begegnet, die Relevanz im Bezug zur Praxis und Bedeutung im sich ständig ändernden Bereich der Cybersecurity erhöht. Trotz dieser Einschränkungen bietet die Tabelle, meiner Meinung nach, eine robuste Basis, die ein umfassendes Verständnis der grundlegenden Sicherheitsrisiken nachweist.


