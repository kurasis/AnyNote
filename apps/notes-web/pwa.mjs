// Installation and storage guidance contain no account/content state. Updates
// use the browser's waiting-worker lifecycle; never skip waiting over live vaults.
const labels = {
  en: {
    help: 'Install and storage', install: 'On iPhone, open this site in Safari, choose Share → Add to Home Screen, then open AnyNote from its icon. Keep your recovery kit separately.',
    installed: 'Home Screen app', browser: 'Browser mode', storage: 'Check local storage', persist: 'Request persistent storage',
    estimate: 'Estimated local usage / quota', bytes: 'bytes', unknown: 'Unavailable', granted: 'Persistent storage granted', denied: 'Persistence not granted; keep an independent recovery copy',
    limits: 'Estimates are not guaranteed free space. iOS may stop background work, forget selected files or remove site storage. Transfers pause on lock; unlock and reselect the same source to resume. Removing site data can remove unsent work.',
    update: 'Check for app update', waiting: 'Update downloaded. Save your work and close every AnyNote window, then reopen. Pending encrypted work is retained.',
    current: 'App update check complete', failed: 'Could not check this operation. Existing encrypted work is retained.',
    offline: 'Offline; only verified local content is available', online: 'Connection available; account, device and group access are checked separately after unlock',
    groups: 'Groups', threads: 'Threads', editor: 'Note', back: 'Back', export: 'Saving plaintext to Files or sharing it gives the operating system access to that copy. A PWA cannot withdraw it or guarantee completion in the background.',
  },
  ru: {
    help: 'Установка и хранилище', install: 'На iPhone откройте сайт в Safari, выберите «Поделиться» → «На экран Домой», затем запустите AnyNote с его значка. Храните комплект восстановления отдельно.',
    installed: 'Приложение с экрана Домой', browser: 'Режим браузера', storage: 'Проверить хранилище', persist: 'Запросить постоянное хранение',
    estimate: 'Примерный объём данных / квота', bytes: 'байт', unknown: 'Недоступно', granted: 'Постоянное хранение разрешено', denied: 'Постоянное хранение не разрешено; сохраняйте независимую резервную копию',
    limits: 'Оценка не гарантирует свободное место. iOS может остановить фоновую работу, забыть выбранные файлы или удалить данные сайта. Передача приостанавливается при блокировке: разблокируйте приложение и выберите тот же исходный файл. Очистка сайта может удалить неотправленную работу.',
    update: 'Проверить обновление', waiting: 'Обновление загружено. Сохраните работу, закройте все окна AnyNote и откройте приложение снова. Защищённые незавершённые операции сохраняются.',
    current: 'Проверка обновления завершена', failed: 'Не удалось выполнить проверку. Существующая зашифрованная работа сохранена.',
    offline: 'Нет сети; доступно только проверенное локальное содержимое', online: 'Сеть доступна; после разблокировки вход, устройство и доступ к группе проверяются отдельно',
    groups: 'Группы', threads: 'Разделы', editor: 'Заметка', back: 'Назад', export: 'Сохранение открытого файла в «Файлы» или передача через системное меню даёт ОС доступ к этой копии. PWA не может отозвать её или гарантировать завершение в фоне.',
  },
};

export function storageDescription(estimate, text) {
  const number = value => Number.isSafeInteger(value) && value >= 0 ? String(value) : text.unknown;
  return `${text.estimate}: ${number(estimate?.usage)} / ${number(estimate?.quota)} ${text.bytes ?? 'bytes'}`;
}

export function mountPwa({language, prepareUpdate}) {
  const panel = document.createElement('details');
  panel.id = 'pwa-help';
  const summary = document.createElement('summary');
  const mode = document.createElement('p'), install = document.createElement('p'), limits = document.createElement('p'), handoff = document.createElement('p');
  const status = document.createElement('p');
  status.id = 'pwa-storage-state'; status.setAttribute('role', 'status');
  const updateState = document.createElement('p');
  updateState.id = 'pwa-update-state'; updateState.setAttribute('role', 'status');
  const network = document.createElement('p');
  network.id = 'pwa-network-state'; network.setAttribute('role', 'status');
  const makeButton = (id, action) => {
    const button = document.createElement('button'); button.type = 'button'; button.id = id;
    button.onclick = async () => {
      button.disabled = true;
      try { await action(); } catch { (id === 'pwa-update' ? updateState : status).textContent = text().failed; }
      finally { button.disabled = false; }
    };
    return button;
  };
  const text = () => labels[language()] ?? labels.en;
  const checkStorage = makeButton('pwa-storage', async () => {
    status.textContent = storageDescription(await navigator.storage?.estimate?.(), text());
  });
  const persist = makeButton('pwa-persist', async () => {
    // Only an explicit user gesture requests persistent storage.
    const granted = await navigator.storage?.persist?.() ?? false;
    status.textContent = `${granted ? text().granted : text().denied}. ${storageDescription(await navigator.storage?.estimate?.(), text())}`;
  });
  let registration;
  const showUpdate = () => { if (registration?.waiting) updateState.textContent = text().waiting; };
  const register = async () => {
    if (!navigator.serviceWorker) throw Error('SERVICE_WORKER_UNAVAILABLE');
    registration ??= await navigator.serviceWorker.register('/auth/sw.js', {scope: '/auth/', updateViaCache: 'none'});
    showUpdate();
    registration.addEventListener('updatefound', () => {
      const worker = registration.installing;
      worker?.addEventListener('statechange', showUpdate);
    }, {once: true});
    return registration;
  };
  const update = makeButton('pwa-update', async () => {
    await prepareUpdate();
    const worker = await register();
    await worker.update();
    updateState.textContent = worker.waiting ? text().waiting : text().current;
  });
  panel.append(summary, mode, install, limits, handoff, network, checkStorage, persist, status, update, updateState);
  document.getElementById('status').after(panel);
  const tabs = document.createElement('nav'); tabs.id = 'pwa-panes'; tabs.setAttribute('aria-label', 'Workspace');
  const panes = [...document.querySelectorAll('.panes > .pane')], buttons = [];
  const back = document.createElement('button'); back.type = 'button'; back.id = 'pwa-back';
  let active = 0;
  const select = index => {
    active = index; back.disabled = index === 0;
    panes.forEach((pane, n) => { pane.dataset.mobileActive = String(n === index); });
    buttons.forEach((button, n) => button.setAttribute('aria-pressed', String(n === index)));
  };
  for (const [index, key] of ['groups', 'threads', 'editor'].entries()) {
    const button = document.createElement('button'); button.type = 'button';
    button.onclick = () => select(index); button.dataset.label = key;
    tabs.append(button); buttons.push(button);
  }
  back.onclick = () => select(Math.max(0, active - 1)); tabs.append(back);
  document.querySelector('.panes').before(tabs); select(0);
  const connection = () => { network.textContent = text()[navigator.onLine ? 'online' : 'offline']; };
  addEventListener('online', connection); addEventListener('offline', connection);
  const translate = () => {
    summary.textContent = text().help; install.textContent = text().install; limits.textContent = text().limits; handoff.textContent = text().export;
    mode.textContent = text()[matchMedia('(display-mode: standalone)').matches || navigator.standalone ? 'installed' : 'browser'];
    checkStorage.textContent = text().storage; persist.textContent = text().persist; update.textContent = text().update;
    buttons.forEach(button => { button.textContent = text()[button.dataset.label]; });
    back.textContent = text().back;
    connection(); showUpdate();
  };
  translate();
  // Registering a static-only worker requires no account access or vault keys.
  register().catch(() => {});
  return {translate, select};
}
