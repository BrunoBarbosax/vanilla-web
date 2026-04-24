const CACHE_NAME = "vanilla-app-v1";

self.addEventListener("install", event => {
  console.log("Service Worker instalado");
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  console.log("Service Worker ativo");
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", event => {
  event.respondWith(fetch(event.request));
});