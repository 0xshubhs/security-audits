'use strict';
// PoC: does SWR's module-global INITIAL_CACHE / default cache leak one server
// request's data into another's server-rendered HTML (SSR request isolation)?
// swr@2.5.1, react/react-dom@18, rendered with renderToStaticMarkup (server path).
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const useSWR = require('swr').default;
const { SWRConfig, useSWRConfig, unstable_serialize } = require('swr');
const { cache, mutate } = require('swr/_internal'); // default cache + global mutate

const KEY = '/api/me';

// A component that renders whatever SWR returns for KEY on the server.
function Profile() {
  const { data } = useSWR(KEY, null); // fetcher null => no fetch; server returns snapshot
  return React.createElement('div', { id: 'out' }, 'data=' + JSON.stringify(data));
}

// Render a "request" with its OWN per-request provider (documented SSR isolation).
function renderRequest(providerMap) {
  const tree = React.createElement(
    SWRConfig,
    { value: { provider: () => providerMap } },
    React.createElement(Profile, null)
  );
  return renderToStaticMarkup(tree);
}

console.log('=== SWR SSR isolation PoC (swr@' + require('swr/package.json').version + ') ===\n');

// ---- Scenario 1: default module-global cache shared across requests (no provider) ----
function renderDefault() {
  return renderToStaticMarkup(React.createElement(Profile, null));
}
console.log('[Scenario 1] default cache shared across requests (no per-request provider)');
// Request A populates the default cache with a secret via mutate (server-side seeding).
mutate(KEY, { name: 'ALICE_SECRET_SSN_123' }, false);
const s1a = renderDefault();
console.log('  Request A (Alice) HTML :', s1a);
// Request B: a different user hits the SAME server process, no reset.
const s1b = renderDefault();
console.log('  Request B (Bob)   HTML :', s1b);
console.log('  >> LEAK?', s1b.includes('ALICE_SECRET') ? 'YES — Bob sees Alice data' : 'no');
console.log('');

// ---- Scenario 2: per-request provider isolation, but INITIAL_CACHE is global ----
console.log('[Scenario 2] per-request provider (documented isolation) + global INITIAL_CACHE');
// Fresh key so scenario1 state does not interfere.
const KEY2 = '/api/session';
function Profile2() {
  const { data } = useSWR(KEY2, null);
  return React.createElement('div', { id: 'out2' }, 'data=' + JSON.stringify(data));
}
function renderRequest2(providerMap) {
  const tree = React.createElement(
    SWRConfig,
    { value: { provider: () => providerMap } },
    React.createElement(Profile2, null)
  );
  return renderToStaticMarkup(tree);
}
// Request A: raw-seed the DEFAULT cache then mutate so INITIAL_CACHE[KEY2] captures Alice's value.
cache.set(KEY2, { data: { name: 'ALICE_TOKEN_abc' } });
mutate(KEY2); // revalidate -> setCache -> INITIAL_CACHE[KEY2] = prev (Alice)
// Request B: a DIFFERENT user, with a FRESH empty per-request provider map.
const mapB = new Map();
const s2b = renderRequest2(mapB);
console.log('  Request B (Bob) fresh provider HTML :', s2b);
console.log('  >> LEAK across provider boundary?',
  s2b.includes('ALICE_TOKEN') ? 'YES — INITIAL_CACHE defeated per-request isolation' : 'no');
