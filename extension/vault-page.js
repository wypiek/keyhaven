import { mountApp } from './ui/app.js';
import { backend } from './bridge.js';

const item = new URLSearchParams(location.hash.slice(1)).get('item');
mountApp(document.getElementById('app'), { ...backend, initialItem: item });
