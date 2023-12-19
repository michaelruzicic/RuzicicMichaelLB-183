# Schwachstellen in Appilkationen: Von der Erkennung zur Absicherung




## Introduktion

In der heutigen digitalisierten Welt, in der Anwendungen das Rückgrat zahlreicher Geschäftsprozesse bilden, ist die Sicherheit dieser Anwendungen entscheidender denn je. Das Ziel dieses ePortfolios ist es, meine tiefe Auseinandersetzung mit den Kernaspekten der Applikationssicherheit zu dokumentieren, ein Feld, das ständig im Wandel ist und stets neue Herausforderungen mit sich bringt. Im Rahmen des [Moduls 183](https://www.modulbaukasten.ch/module/183/3/de-DE?title=Applikationssicherheit-implementieren) habe ich mich intensiv mit fünf zentralen Handlungszielen beschäftigt:

| HZ | Handlungsziel                                                                                               |
|----|-------------------------------------------------------------------------------------------------------------|
| I  | Aktuelle Bedrohungen erkennen und erläutern können. Aktuelle Informationen zum Thema beschaffen und mögliche Auswirkungen aufzeigen und erklären können. |
| II  | Sicherheitslücken und ihre Ursachen in einer Applikation erkennen können. Gegenmassnahmen vorschlagen und implementieren können. |
| III  | Mechanismen für die Authentifizierung und Autorisierung umsetzen können.                                    |
| IV  | Sicherheitsrelevante Aspekte bei Entwurf, Implementierung und Inbetriebnahme berücksichtigen.               |
| V  | Informationen für Auditing und Logging generieren. Auswertungen und Alarme definieren und implementieren.   |

## Handlungsziel I
### Artefakt: OWASP Top Ten 2021 Tabelle

| Rang | Risiko                           | Beschreibung                                                                                       | Erkennungsmethoden                                                   | Gegenmassnahmen                                                                           |
|------|----------------------------------|----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| 1    | Broken Access Control            | Unzureichende Einschränkung der Zugriffsrechte, die zu unbefugtem Zugriff führen kann.             | Überprüfung von Zugriffsprotokollen, Penetrationstests               | Implementierung von rollenbasierten Zugriffskontrollen, Prinzip der minimalen Rechte     |
| 2    | Cryptographic Failures           | Schwachstellen in der Verschlüsselung, die zur Offenlegung sensibler Daten führen können.          | Sicherheitsüberprüfungen der Kryptographie, Code-Reviews             | Verwendung sicherer und aktueller Kryptographiestandards, sichere Schlüsselverwaltung    |
| 3    | Injection                        | Einschleusen von bösartigem Code durch Eingabefelder, z.B. SQL, NoSQL, OS Command Injection.       | Eingabedatenvalidierung, Sicherheitsüberprüfungen                    | Verwendung von Prepared Statements und ORM-Frameworks, Validierung aller Eingaben        |
| 4    | Insecure Design                  | Mangel an Sicherheitsmassnahmen im Design und Architektur der Software.                             | Threat Modelling, Architekturüberprüfungen                           | Anwendung von Secure-Design-Prinzipien, regelmässige Sicherheitsaudits                    |
| 5    | Security Misconfiguration        | Fehlkonfigurationen, die zu Sicherheitslücken führen können, z.B. ungeschützte Datenbanken.        | Automatisierte Konfigurationsüberprüfungen, Sicherheitsaudits        | Strenge Konfigurationsmanagementprozesse, regelmässige Updates und Patches                |
| 6    | Vulnerable and Outdated Components | Verwendung veralteter oder unsicherer Komponenten in der Software.                               | Softwarekompositionsanalyse, regelmässige Abhängigkeitsüberprüfungen  | Aktualisierung auf die neuesten sicheren Versionen, Verwendung sicherer Bibliotheken     |
| 7    | Identification and Authentication Failures | Schwächen in der Identifikation und Authentifizierung, die zu unbefugtem Zugriff führen können. | Überprüfung der Authentifizierungsprotokolle, Penetrationstests      | Multi-Faktor-Authentifizierung, robuste Passwortrichtlinien                                |
| 8    | Software and Data Integrity Failures | Mangelnde Integritätsprüfungen, die zu unautorisierten Datenänderungen führen können.             | Integritätsüberprüfungen, Code-Signierung                            | Verwendung von Code-Signierung, Implementierung von Integritätsprüfungen                 |
| 9    | Security Logging and Monitoring Failures | Unzureichende Protokollierung und Überwachung, die das Erkennen von Sicherheitsvorfällen verhindert. | Überprüfung von Protokollen und Alarmen, Sicherheitsaudits          | Implementierung umfassender Protokollierungs- und Überwachungssysteme                    |
| 10   | Server-Side Request Forgery (SSRF) | Angriffe, bei denen der Server dazu gebracht wird, unerwünschte Aktionen auszuführen.               | Netzwerküberwachung, Sicherheitsüberprüfungen                        | Beschränkung ausgehender Anfragen, Verwendung sicherer Programmierpraktiken             |

**Nachweis der Zielerreichung:**
Die Tabelle zeigt meine Fähigkeit, knifflig Sicherheitsrisiken zu identifizieren und zu analysieren. Sie wurde eigenständig recherchiert und zusammengefasst, wodurch ich mein Wissen über Erkennungsmethoden und Gegenmassnahmen erwitern konnte.

**Erklärung des Artefakts:**
Die Tabelle bietet einen umfassenden Überblick über die zehn grössten Sicherheitsrisiken im Bereich der Webanwendungssicherheit (Stand 2021), einschliesslich deren Beschreibung, Erkennungsmethoden und Gegenmassnahmen. Sie dient als kompaktes Recherchemittel für die wichtigsten Bedrohungen und deren Abwehrmöglichkeiten.

**Kritische Beurteilung:**
Die OWASP Top Ten 2021 Tabelle erweist sich als ein effektives Instrument, um die zentralen Bedrohungen in der Applikationssicherheit abzubilden. Sie bietet eine solide Übersicht über kritische Sicherheitsrisiken. Da die Tabelle die Sicherheitsrisiken von 2021 abbildet, hätte eine Erweiterung mit Diskussionen über aktuelle "Angriffstrends" und wie man ihnen begegnet, die Bedeutung im sich ständig ändernden Bereich der Cybersecurity erhöht. Ausserdem kann man diesem Artefakt noch zusätzliche Minuspunkte geben, da sie diese Begrifflichkeiten nur oberflächlich beschreibt und keine praxisbezogene Beispiele vorweist. Trotz diesen Einschränkungen bietet die Tabelle, meiner Meinung nach, eine robuste Basis, die ein umfassendes Verständnis der grundlegenden Sicherheitsrisiken bietet.

## Handlungsziel 2

#### LoginController - Artefakt vorher:
```csharp
using M183.Controllers.Dto;
using M183.Controllers.Helper;
using M183.Data;
using M183.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace M183.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly NewsAppContext _context;

        public LoginController(NewsAppContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Login a user using password and username
        /// </summary>
        /// <response code="200">Login successfull</response>
        /// <response code="400">Bad request</response>
        /// <response code="401">Login failed</response>
        [HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public ActionResult<User> Login(LoginDto request)
        {
            if (request == null || request.Username.IsNullOrEmpty() || request.Password.IsNullOrEmpty())
            {
                return BadRequest();
            }

            string sql = string.Format("SELECT * FROM Users WHERE username = '{0}' AND password = '{1}'", 
                request.Username, 
                MD5Helper.ComputeMD5Hash(request.Password));

            User? user= _context.Users.FromSqlRaw(sql).FirstOrDefault();
            if (user == null)
            {
                return Unauthorized("login failed");
            }
            return Ok(user);
        }
    }
}
```

#### LoginController - Artefakt nachher:

```csharp
using M183.Controllers.Dto;
using M183.Controllers.Helper;
using M183.Data;
using M183.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace M183.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly NewsAppContext _context;

        public LoginController(NewsAppContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Login a user using password and username
        /// </summary>
        /// <response code="200">Login successfull</response>
        /// <response code="400">Bad request</response>
        /// <response code="401">Login failed</response>
        [HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public ActionResult<User> Login(LoginDto request)
        {
            if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest();
            }

            string sql = "SELECT * FROM Users WHERE username = @Username AND password = @Password";

            SqlParameter usernameParameter = new SqlParameter("@Username", request.Username);
            SqlParameter passwordParameter = new SqlParameter("@Password", MD5Helper.ComputeMD5Hash(request.Password));

            User? user = _context.Users.FromSqlRaw(sql, usernameParameter, passwordParameter).FirstOrDefault();
            if (user == null)
            {
                return Unauthorized("Login failed");
            }

            return Ok(user);
        }
    }
}
```

**Nachweis der Zielerreichung:** Der zweite Code zeigt eine Verbesserung in Bezug auf die Sicherheit gegenüber dem vorherigen Code. Dies wird durch die Verwendung parameterisierter SQL-Abfragen mit SQL-Parametern deutlich, was SQL Injection-Angriffe verhindert. Das Ziel, Sicherheitslücken zu erkennen und Gegenmassnahmen zu implementieren, wurde erreicht.

**Erklärung der Artefakte:** Die beiden Codebeispiele repräsentieren eine "LoginController"-Klasse in einer Beispielapplikation. Der vorherige Code verwendete eine unsichere Methode, um Benutzereingaben in SQL-Abfragen einzufügen, während der nachherige Code Sicherheitsverbesserungen durch die Verwendung von parameterisierten Abfragen und SQL-Parametern aufzeigt.

**Kritische Beurteilung:** Der vorherige Code wies erhebliche Sicherheitslücken auf, da er anfällig für SQL Injection-Angriffe war. Dies hätte schwerwiegende Sicherheitsprobleme in der Anwendung verursachen können. Der nachherige Code stellt eine wesentliche Verbesserung dar, indem er die Sicherheit der Anwendung erhöht. Es ist jedoch wichtig zu beachten, dass Sicherheit eine kontinuierliche Anstrengung ist, und zusätzliche Sicherheitsaspekte wie Authentifizierung und Autorisierung sollten ebenfalls in Betracht gezogen werden.
