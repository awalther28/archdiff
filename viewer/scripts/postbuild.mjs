// GitHub Pages has no server-side rewrites. We use HashRouter so deep links
// never hit the server, but a 404.html copy of index.html is shipped anyway
// so a stray non-hash URL still boots the app. `.nojekyll` stops Pages from
// running Jekyll, which would otherwise drop files/dirs starting with "_".
import { copyFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const dist = join(process.cwd(), 'dist');
if (!existsSync(join(dist, 'index.html'))) {
  console.error('postbuild: dist/index.html not found');
  process.exit(1);
}
copyFileSync(join(dist, 'index.html'), join(dist, '404.html'));
writeFileSync(join(dist, '.nojekyll'), '');
console.log('postbuild: wrote dist/404.html and dist/.nojekyll');
