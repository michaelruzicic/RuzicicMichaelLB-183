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
Die Tabelle zeigt meine Fähigkeit, knifflige Sicherheitsrisiken zu identifizieren und zu analysieren. Sie wurde eigenständig recherchiert und zusammengefasst, wodurch ich mein Wissen über Erkennungsmethoden und Gegenmassnahmen erwitern konnte.

**Erklärung des Artefakts:**
Die Tabelle bietet einen umfassenden Überblick über die zehn grössten Sicherheitsrisiken im Bereich der Webanwendungssicherheit (Stand 2021), einschliesslich deren Beschreibung, Erkennungsmethoden und Gegenmassnahmen. Sie dient als kompaktes Recherchemittel für die wichtigsten Bedrohungen und deren Abwehrmöglichkeiten.

**Kritische Beurteilung:**
Die OWASP Top Ten 2021 Tabelle erweist sich als ein effektives Instrument, um die zentralen Bedrohungen in der Applikationssicherheit abzubilden. Sie bietet eine solide Übersicht über kritische Sicherheitsrisiken. Da die Tabelle die Sicherheitsrisiken von 2021 abbildet, hätte eine Erweiterung mit Diskussionen über aktuelle "Angriffstrends" und wie man ihnen begegnet, die Bedeutung im sich ständig ändernden Bereich der Cybersecurity erhöht. Ausserdem kann man diesem Artefakt noch zusätzliche Minuspunkte geben, da sie diese Begrifflichkeiten nur oberflächlich beschreibt und keine praxisbezogene Beispiele vorweist. Trotz diesen Einschränkungen bietet die Tabelle, meiner Meinung nach, eine robuste Basis, die ein umfassendes Verständnis der grundlegenden Sicherheitsrisiken bietet.

## Handlungsziel II

Verstanden! Hier sind die kürzeren Versionen der beiden Artefakte für den LoginController "nachher":

#### Artefakt 1 - Code vorher:
```csharp
using M183.Controllers.Dto;
using M183.Data;
using M183.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

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

            var user = _context.Users.FirstOrDefault(u => u.Username == request.Username && u.Password == request.Password);
            if (user == null)
            {
                return Unauthorized("Login failed");
            }

            return Ok(user);
        }
    }
}
```

#### Artefakt 2 - Code nachher:
```csharp
using M183.Controllers.Dto;
using M183.Data;
using M183.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

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

            var user = _context.Users.FromSqlRaw(sql, usernameParameter, passwordParameter).FirstOrDefault();
            if (user == null)
            {
                return Unauthorized("Login failed");
            }

            return Ok(user);
        }
    }
}
```

Es handelt sich um die gleichen Artefakte wie zuvor, nur in gekürzterer Form, um nur die wichtigsten Änderungen zu zeigen.
**Nachweis der Zielerreichung:** Der zweite Code zeigt eine Verbesserung in Bezug auf die Sicherheit gegenüber dem vorherigen Code. Dies wird durch die Verwendung parameterisierter SQL-Abfragen mit SQL-Parametern deutlich, was SQL Injection-Angriffe verhindert. Das Ziel, Sicherheitslücken zu erkennen und Gegenmassnahmen zu implementieren, wurde erreicht.

**Erklärung der Artefakte:** Die beiden Codebeispiele repräsentieren eine "LoginController"-Klasse in einer Beispielapplikation. Der vorherige Code verwendete eine unsichere Methode, um Benutzereingaben in SQL-Abfragen einzufügen, während der nachherige Code Sicherheitsverbesserungen durch die Verwendung von parameterisierten Abfragen und SQL-Parametern aufzeigt.

**Kritische Beurteilung:** Der vorherige Code wies erhebliche Sicherheitslücken auf, da er ungeschützt gegen SQL Injection-Angriffe war. Dies hätte schwerwiegende Sicherheitsprobleme in der Anwendung verursacht. Der nachherige Code stellt eine deutliche Verbesserung dar, indem er die Sicherheit der Anwendung erhöht. 

## Handlungsziel III



## Artefakt 1 - Code vorher:
```csharp
using M183.Controllers.Dto;
    ...
    public class LoginController : ControllerBase
    {
        ...
        [HttpPost]
        public ActionResult<User> Login(LoginDto request)
        {
            ...
            User? user = _context.Users.FromSqlRaw(sql, usernameParameter, passwordParameter).FirstOrDefault();
            ...
        }
    }
}
```

## Artefakt 2 - Code nachher:
```csharp
using M183.Controllers.Dto;
    ...
public class LoginController : ControllerBase
    ...
    {
        ...
        [HttpPost]
        public ActionResult<string> Login(LoginDto request)
        {
            ...
            var user = _context.Users.FirstOrDefault(u => u.Username == request.Username && u.Password == request.Password);
            ...
        }
    }
}
```

## Kompletter Code des überarbeiteten LoginControllers:
```csharp
using M183.Controllers.Dto;
using M183.Controllers.Helper;
using M183.Data;
using M183.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace M183.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly NewsAppContext _context;
        private readonly IConfiguration _configuration;

        public LoginController(NewsAppContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        [HttpPost]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public ActionResult<string> Login(LoginDto request)
        {
            if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest();
            }

            var user = _context.Users.FirstOrDefault(u => u.Username == request.Username && u.Password == request.Password);
            if (user == null)
            {
                return Unauthorized("Login failed");
            }

            ...
            return Ok(tokenString);
        }
    }
}
```

## Nachweis der Zielereichung
Die Zielereichung wird durch das überarbeitete Artefakt, den LoginController mit der Implementierung des JwtAuthenticationService, erreicht. Dies ermöglicht die sicherere Authentifizierung und Autorisierung von Benutzern in der Anwendung.

## Erklärung der Artefakte (Codes)
Das Artefakt besteht aus dem überarbeiteten Code des LoginControllers. Dieser verwendet den JwtAuthenticationService, um Benutzer zu authentifizieren und JWT-Tokens zu generieren. Der Benutzer wird anhand des Benutzernamens und des Passworts überprüft. Bei erfolgreicher Authentifizierung wird ein JWT-Token generiert und zurückgegeben.

## Kritische Beurteilung
Die Umsetzung des Artefakts erfüllt das Handlungsziel, stellt jedoch nur eine Grundlage für die sichere Authentifizierung und Autorisierung dar. Weitere Sicherheitsaspekte wie die sichere Übertragung von Daten müssen ebenfalls berücksichtigt werden. Der Code des Artefakts kann weiter verbessert werden, um Schwachstellen und Sicherheitsrisiken zu minimieren.
