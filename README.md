# Software Engineer Security Training

Training slides designed to provide a basic level of security training for software engineers working in an environment which values security.

[Instaclustr](https://www.instaclustr.com/) released this content under the Creative Commons Attribution-ShareAlike 4.0 license in the hope that other organisations can benefit from it, and contribute back to improve our own security training.

The content was initially initially developed as part of our regular security training for Instaclustr managed platform developers, but is designed to be generic enough to be easily adapted to the specific requirement of any organisation and technical stack.

The base version here covers all the topics required by the [PCI DSS section 6.5 requirements](https://www.pcisecuritystandards.org/document_library), the 2021 version of the [OWASP Top Ten](https://owasp.org/Top10/) and the [CWE/SANS TOP 25 Most Dangerous Software Errors](https://www.sans.org/top25-software-errors/). While many topics within can not possibly be explored in complete detail in a single training session, we have found that providing software engineers with a broad survey of common security issues prepares them to undertake deeper research in specific areas when the need arises in the course of their day-to-day work.

The slides are written in the [Marp (Markdown Presentation Ecosystem)](https://marp.app/) format to facilitate a pull-request collaboration model and to provide users with the ability to fork the base slides and add their own content easily while retaining the ability to merge in upstream improvements over time.

## Building the slides

After cloning the repository, run `build.sh` from the repository's top level directory to generate PDF, PPTX and HTML presentation files into the target directory.

Note that docker must be available as the build process relies on the official [marp-cli docker image](https://github.com/marp-team/marp-cli/#docker).

## Editing the slides

The `docs/slides.md` file can easily be edited in any text editor, however the [Marp for VS Code](https://marketplace.visualstudio.com/items?itemName=marp-team.marp-vscode) plugin provides a convenient preview view which may be helpful during editing.

The syntax within the slides file is [Marpit Markdown](https://marpit.marp.app/markdown), which is built on the common markdown syntax with some special syntax to support separating slides and other presentation specific functionality.

Obviously we encourage you to adapt the base content here to your team's specific technology stack and incorporate examples for the specific libraries and frameworks that your team uses most frequently.

## Presenting the slides

We currently present these slides internally to our development team, with a number of extra slides specific to our internal environments, in a single 90 minute session. Your milage may vary, especially when presenting them for the first time!

## Support

Though we may update it from time to time, this content is an 'Unsupported Tool' as per the [Instaclustr Open Source Project Status](https://www.instaclustr.com/support/documentation/announcements/instaclustr-open-source-project-status/).

## Credits

Some structure and examples are based on:

- The Open Web Application Security Project, under their Creative Commons Attribution Share-Alike 4.0 license. See https://owasp.org/Top10/A00-about-owasp/#copyright-and-license
- The MITRE Corporation’s Common Weakness Enumeration (CWE) site. See https://cwe.mitre.org/about/termsofuse.html


>  The MITRE Corporation ("MITRE") has copyrighted the CWE List, Top 25, CWSS, and CWRAF for the benefit of the community in order to ensure each remains a free and open standard, as well as to legally protect the ongoing use of it and any resulting content by government, vendors, and/or users. CWE is a trademark of MITRE. Please contact cwe@mitre.org if you require further clarification on this issue.
>  MITRE hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE’s copyright designation and this license in any such copy.

Prior to developing this training course, Instaclustr used an adapted
version of [the 'Security Training for Engineers' course open sourced by PagerDuty](https://github.com/PagerDuty/security-training/blob/master/docs/for_engineers/index.md) which inspired us to open source ours. That one and might be a great starting point if ours doesn't suit you.