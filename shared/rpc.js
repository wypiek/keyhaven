// Method table exposed to trusted UIs (extension pages, web vault). Content scripts never
// reach this directly; the extension background filters what pages can ask for.

import { VaultClient } from './vault.js';
import { importFile } from './importers.js';

export async function dispatch(vault, method, p = {}) {
  await vault.ready;
  const touchy = !['status', 'serverInfo', 'sync', 'icons'].includes(method);
  if (touchy && vault.unlocked) await vault.touch();
  switch (method) {
    case 'status': return vault.status();
    case 'serverInfo': return VaultClient.serverInfo(p.url, p.allowInsecure);
    case 'register': return vault.register(p);
    case 'login': return vault.login(p);
    case 'unlock': return vault.unlock(p.password);
    case 'lock': return vault.lock();
    case 'logout': return vault.logout();
    case 'sync': await vault.sync(); return vault.status();
    case 'list': return vault.listItems();
    case 'get': return vault.getItem(p.id);
    case 'save': return vault.saveItem(p.item);
    case 'trash': return vault.trashItem(p.id);
    case 'restore': return vault.restoreItem(p.id);
    case 'delete': return vault.deleteItem(p.id);
    case 'emptyTrash': return vault.emptyTrash();
    case 'favorite': return vault.patchItem(p.id, { favorite: !!p.value });
    case 'markUsed': return vault.markUsed(p.id);
    case 'import': return vault.importItems(importFile(p.text, p.filename));
    case 'export': return vault.exportItems(p.password, p.format);
    case 'changePassword': return vault.changePassword(p.current, p.next);
    case 'deleteAccount': return vault.deleteAccount(p.password);
    case 'sessions': return vault.sessions();
    case 'revokeSession': return vault.revokeSession(p.id);
    case 'settings': return vault.updateSettings(p.patch || {});
    case 'health': return vault.health();
    case 'match': return vault.matchLogins(p.url);
    case 'admin': return vault.admin(p.method, p.path, p.body);
    case 'refreshInstance': await vault.refreshInstance(); return vault.status();
    case 'icons': return vault.icons(Array.isArray(p.hosts) ? p.hosts.slice(0, 200) : []);
    default: throw new Error(`Unknown method ${method}`);
  }
}
