# Third-party notices for blackboard SVG export

This file is the maintained notice for the SVG export dependencies. Vite copies it and the `licenses/` directory unchanged from `public/` into the frontend distribution. It does not change the license of SecMind or of unrelated upstream components.

## cytoscape-svg 0.4.0

- Author recorded in the published package: Ilkin Safarli.
- License recorded in the published package: GNU GPLv3 (GNU General Public License, version 3).
- Unmodified license text: [licenses/cytoscape-svg-GPL-3.0.txt](licenses/cytoscape-svg-GPL-3.0.txt).
- Public source repository: https://github.com/kinimesi/cytoscape-svg
- Exact versioned npm source distribution: https://registry.npmjs.org/cytoscape-svg/-/cytoscape-svg-0.4.0.tgz
- The dependency is used without local modifications. SecMind's separate integration is in `src/app/blackboardSvg.js`; its exact dependency is pinned in `package-lock.json`.
- The package's GPL text contains the Free Software Foundation's license-document copyright notice, not a separate author copyright statement. No additional copyright dates have been inferred.

## Bundled canvas2svg

The published cytoscape-svg bundle contains canvas2svg. Its package build dependency identifies the public fork and revision below; that revision's source header identifies Canvas 2 Svg v1.0.19, author Kerry Liu, and `Copyright (c) 2014 Gliffy Inc.`.

- License: MIT.
- Copyright notice: Copyright (c) 2014 Gliffy Inc.
- Author: Kerry Liu.
- Public source repository: https://github.com/kinimesi/canvas2svg
- Corresponding revision: https://github.com/kinimesi/canvas2svg/tree/68b8ef886ca066d07294d9ee3157f6a3a9e44599
- Original license text, including the copyright and permission notice: [licenses/canvas2svg-MIT.txt](licenses/canvas2svg-MIT.txt).
- The MIT text was retrieved verbatim from that revision's `LICENSE`; it is retained separately because the minified cytoscape-svg bundle does not preserve the source header.

## Distribution scope

Keep this notice and both license files with frontend distributions. Public upstream source locations above identify the third-party sources; they do not by themselves establish the availability of the complete corresponding source of a combined SecMind release. The release maintainer must provide the complete corresponding source and any required build/install material under the applicable terms when distributing a covered combined work. The exact SecMind release source URL and project-wide licensing decision belong to the release maintainer and are not asserted or changed by this notice. This inventory is not a legal-compliance guarantee.
