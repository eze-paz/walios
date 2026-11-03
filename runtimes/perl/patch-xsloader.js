// patch-xsloader.js <XSLoader_pm.PL or XSLoader.pm>: a core XS module compiled into perl.wasm
// yields to the same module installed again as a loadable object.
//
// perl.wasm is --all-static: every core XS extension (IO, Cwd, MIME::Base64, Time::HiRes,
// Encode, List::Util...) is linked in and its Foo::bootstrap is defined at startup, so
// XSLoader::load always ran the built-in copy -- also when a newer dual-life version was
// installed in vendor_perl (the farm's perl-io, perl-pathtools...), whose .pm then died with
// "IO object version 1.56 does not match bootstrap parameter 1.55". A dynamic perl (every
// Linux distribution's) has no such case: core's own .so is just the last one on @INC. Here
// the built-in copy plays that part -- used only when no auto/Foo/Foo.so is found on @INC.
const fs = require('fs');
const f = process.argv[2];
const src = fs.readFileSync(f, 'utf8');
const old = '    goto &$boots if defined &$boots;\n';
if (!src.includes(old)) { console.error('patch-xsloader: anchor not found in ' + f); process.exit(1); }
const neu = [
  '    if (defined &$boots) {',
  '        # walios: perl.wasm has the core XS modules compiled in; one installed again as a',
  '        # loadable object (a newer dual-life version) is used instead, as a dynamic perl',
  '        # would find it before core\'s own copy (walios/build/perl/patch-xsloader.js)',
  '        my @walios_p = split /::/, $module;',
  '        my $walios_so = join(\'/\', \'auto\', @walios_p, $walios_p[-1]) . \'.so\';',
  '        goto &$boots unless grep { !ref($_) && -f "$_/$walios_so" } @INC;',
  '        goto \\&XSLoader::bootstrap_inherit;',
  '    }',
  '',
].join('\n');
fs.chmodSync(f, fs.statSync(f).mode | 0o200);   // perl's source tarball ships its files read-only
fs.writeFileSync(f, src.replace(old, neu));
console.log('patch-xsloader: patched ' + f);
