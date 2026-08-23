'use strict';
// Follow-up: (a) suspense path with pre-populated shared cache, (b) correctly
// populate the global INITIAL_CACHE for a key and see if a fresh request leaks it.
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const useSWR = require('swr').default;
const { SWRConfig } = require('swr');
const internal = require('swr/_internal');
const { cache, mutate } = internal;

console.log('=== SWR SSR PoC follow-up (swr@' + require('swr/package.json').version + ') ===\n');

// (a) Suspense: cache already holds Alice on a shared server; does a plain render leak it?
const K = '/api/a';
mutate(K, { name: 'ALICE_SECRET' }, false); // seed shared default cache (also locks INITIAL_CACHE[K])
function SusProfile() {
  const { data } = useSWR(K, () => ({ name: 'FETCHED' }), { suspense: true });
  return React.createElement('div', null, 'susp=' + JSON.stringify(data));
}
try {
  const html = renderToStaticMarkup(React.createElement(SusProfile, null));
  console.log('(a) suspense render (cache=Alice):', html);
  console.log('    >> LEAK?', html.includes('ALICE_SECRET') ? 'YES' : 'no');
} catch (e) {
  console.log('(a) suspense threw (promise/suspend):', String(e).slice(0, 80));
}
console.log('');

// (b) Directly populate global INITIAL_CACHE[K2] with Alice, then render a fresh
//     request with an empty per-request provider for the SAME key.
const K2 = '/api/b';
function Prof(props) {
  const { data } = useSWR(props.k, null);
  return React.createElement('div', null, 'v=' + JSON.stringify(data));
}
// Populate INITIAL_CACHE the way the setter does: need cache to hold Alice, then a real setCache.
// Use the internal createCacheHelper against the DEFAULT cache to force the write with prev=Alice.
cache.set(K2, { data: { name: 'ALICE_TOKEN' } });          // raw seed (bypasses INITIAL_CACHE)
const helper = internal.createCacheHelper(cache, K2);
// helper = [get, set, subscribe, getServerSnapshot]
helper[1]({ data: { name: 'NEWER' } });                    // set() -> INITIAL_CACHE[K2] = prev (Alice)
console.log('(b) INITIAL_CACHE[K2] getServerSnapshot():', JSON.stringify(helper[3]()));
// Now a fresh request (different user) with its OWN empty provider map, same key:
const mapB = new Map();
const treeB = React.createElement(
  SWRConfig, { value: { provider: () => mapB } },
  React.createElement(Prof, { k: K2 })
);
const htmlB = renderToStaticMarkup(treeB);
console.log('    Bob fresh-provider render:', htmlB);
console.log('    >> LEAK across provider via INITIAL_CACHE?', htmlB.includes('ALICE_TOKEN') ? 'YES' : 'no');
