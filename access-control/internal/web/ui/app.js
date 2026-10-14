'use strict';
const $ = (s) => document.querySelector(s);
let user = null, requiredPassword = false, submitAction = null, toastTimer;
async function api(action, values = {}) {
  const response = await fetch('/api', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action,...values})});
  const data = await response.json();
  if (data.ended) endScreen(data.error);
  if (!response.ok) throw new Error(data.error || 'Не удалось выполнить действие.');
  return data;
}
function message(error) { return error instanceof TypeError ? 'Нет связи с приложением. Проверьте, что программа запущена.' : error.message; }
function toast(text) {clearTimeout(toastTimer);$('#toast').textContent=text;$('#toast').hidden=false;toastTimer=setTimeout(()=>$('#toast').hidden=true,3500);}
function endScreen(text) {user=null;$('#login-form').reset();resetPasswords($('#login-form'));$('#users').replaceChildren();clearPasswordView();if($('#modal').open)$('#modal').close();if($('#password-modal').open)$('#password-modal').close();$('#login').hidden=true;$('#workspace').hidden=true;$('#ended').hidden=false;if(text)$('#end-message').textContent=text;document.querySelectorAll('nav button').forEach(b=>b.disabled=true);}
async function logout() {
  try {
    await api('logout');
    user = null;
    clearPasswordView();
    if ($('#modal').open) $('#modal').close();
    $('#login-form').reset();
    $('#login-form .error').textContent = '';
    $('#page-error').textContent = '';
    $('#users').replaceChildren();
    resetPasswords($('#login-form'));
    await render();
    $('#login-form [name=name]').focus();
  } catch (error) { toast(message(error)); }
}
// Keep the editable element a regular text input throughout its lifetime.
// Mask in a separate canvas: native password modes (including text-security)
// can restrict macOS input sources after the first character is entered.
const passwordMasks = new WeakMap();
function setPasswordVisible(input, shown) {
  input.classList.toggle('password-masked', !shown);
  const toggle = input.parentElement.querySelector('.password-toggle');
  toggle.setAttribute('aria-pressed', String(shown));
  toggle.setAttribute('aria-label', shown ? 'Скрыть пароль' : 'Показать пароль');
  toggle.title = toggle.getAttribute('aria-label');
  passwordMasks.get(input)?.();
}
function attachPasswordMask(input, control) {
  const canvas = document.createElement('canvas');
  canvas.className = 'password-mask';
  canvas.setAttribute('aria-hidden', 'true');
  control.append(canvas);
  const context = canvas.getContext('2d');
  const segments = new Intl.Segmenter(undefined, {granularity: 'grapheme'});
  const draw = () => {
    const style = getComputedStyle(input);
    const width = input.clientWidth;
    const height = input.clientHeight;
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    context.scale(ratio, ratio);
    context.clearRect(0, 0, width, height);
    if (!input.classList.contains('password-masked')) return;
    context.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
    context.fillStyle = style.caretColor;
    const left = parseFloat(style.paddingLeft);
    const right = width - parseFloat(style.paddingRight);
    context.beginPath();
    context.rect(left, 0, Math.max(0, right - left), height);
    context.clip();
    let x = left - input.scrollLeft;
    for (const {segment} of segments.segment(input.value)) {
      const advance = context.measureText(segment).width;
      context.beginPath();
      context.arc(x + advance / 2, height / 2, 2.5, 0, Math.PI * 2);
      context.fill();
      x += advance;
    }
  };
  passwordMasks.set(input, draw);
  for (const event of ['input', 'scroll', 'focus', 'select', 'keyup', 'click', 'compositionend']) {
    input.addEventListener(event, draw);
  }
  for (const event of ['copy', 'cut', 'dragstart']) {
    input.addEventListener(event, e => {
      if (input.classList.contains('password-masked')) e.preventDefault();
    });
  }
}
window.addEventListener('resize', () => {
  document.querySelectorAll('.password-control input').forEach(input => passwordMasks.get(input)?.());
});
function resetPasswords(root) {
  root.querySelectorAll('.password-control input').forEach(input => setPasswordVisible(input, false));
}
function enhancePasswords(root) {
  root.querySelectorAll('input[type=password], input[data-password]').forEach(original => {
    let input = original;
    if (input.parentElement.classList.contains('password-control')) return;
    input.dataset.password = '';
    // Replace native inputs rather than preserving Chromium's password history.
    if (input.type === 'password') {
      input = document.createElement('input');
      for (const {name, value} of original.attributes) {
        if (name !== 'type') input.setAttribute(name, value);
      }
      input.value = original.value;
      original.replaceWith(input);
    }
    input.type = 'text';
    input.autocomplete = 'off';
    input.classList.add('password-masked');
    const control = document.createElement('span');
    control.className = 'password-control';
    input.before(control);
    control.append(input);
    input.inputMode = 'text';
    input.autocapitalize = 'off';
    input.setAttribute('autocorrect', 'off');
    input.spellcheck = false;
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'password-toggle';
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const eye = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    eye.setAttribute('d', 'M2 12c2.5-4 6-6 10-6s7.5 2 10 6c-2.5 4-6 6-10 6S4.5 16 2 12Z');
    const pupil = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    pupil.setAttribute('cx', '12');
    pupil.setAttribute('cy', '12');
    pupil.setAttribute('r', '3');
    const slash = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    slash.setAttribute('d', 'M3 3 21 21');
    svg.append(eye, pupil, slash);
    toggle.append(svg);
    toggle.addEventListener('click', () => {
      const shown = toggle.getAttribute('aria-pressed') === 'false';
      const start = input.selectionStart;
      const end = input.selectionEnd;
      setPasswordVisible(input, shown);
      input.focus({preventScroll: true});
      if (start !== null && end !== null) input.setSelectionRange(start, end);
    });
    control.append(toggle);
    attachPasswordMask(input, control);
    setPasswordVisible(input, false);
  });
}
function setupMenus() {
  document.querySelectorAll('nav details').forEach(menu => {
    menu.addEventListener('pointerenter', event => {
      if (event.pointerType === 'mouse') {
        document.querySelectorAll('nav details').forEach(other => { if (other !== menu) other.open = false; });
        menu.open = true;
      }
    });
    menu.addEventListener('pointerleave', event => {
      if (event.pointerType === 'mouse') menu.open = false;
    });
    menu.addEventListener('focusout', event => {
      if (!menu.contains(event.relatedTarget)) menu.open = false;
    });
  });
  document.addEventListener('pointerdown', event => {
    if (!event.target.closest('nav details')) document.querySelectorAll('nav details').forEach(menu => menu.open = false);
  });
}
function field(label,name,type='password',autocomplete='new-password') {
  const el=document.createElement('label');el.textContent=label;
  const input = document.createElement('input');
  input.name = name;
  input.autocomplete = autocomplete;
  input.required = true;
  if (type === 'password') {
    input.dataset.password = '';
    input.type = 'text';
    input.classList.add('password-masked');
  } else {
    input.type = type;
    input.maxLength = 64;
  }
  el.append(input);
  // Finish configuring detached fields before the browser can focus them.
  enhancePasswords(el);
  return el;
}
function openDialog(title,description,fields,action,submitText='Сохранить') {
  $('#dialog-title').textContent=title;$('#dialog-description').textContent=description;$('#dialog-fields').replaceChildren(...fields);$('#dialog-form .error').textContent='';$('#submit-modal').hidden=!action;$('#submit-modal').textContent=submitText;$('#cancel-modal').hidden=!action;$('#dialog-form .dialog-actions').hidden=!action;submitAction=action;enhancePasswords($('#dialog-fields'));if(!$('#modal').open)$('#modal').showModal();
}
function clearPasswordView() {
  requiredPassword = false;
  if ($('#password-modal').open) $('#password-modal').close();
  $('#password-form').reset();
  $('#password-fields').replaceChildren();
  $('#password-form .error').textContent = '';
}
function showPasswordScreen(initial=false) {
  requiredPassword=initial;
  const fields=[];
  if(!initial)fields.push(field('Текущий пароль','old','password','current-password'));
  fields.push(field('Новый пароль','password'),field('Повторите новый пароль','confirmation'));
  $('#password-title').textContent=initial?'Установите первый пароль':'Смена пароля';
  $('#password-description').textContent=`${initial?'Перед началом работы задайте непустой пароль. ':'Подтвердите текущий пароль и задайте новый. '}${user.restricted?'Обязательны латинская и кириллическая буквы.':'Ограничение по алфавитам отключено.'}`;
  $('#password-fields').replaceChildren(...fields);
  $('#password-form .error').textContent='';
  $('#cancel-password').textContent=initial?'Завершить программу':'Отмена';
  $('#submit-password').textContent=initial?'Установить пароль':'Изменить пароль';
  enhancePasswords($('#password-fields'));
  $('#workspace').hidden=true;
  if (!$('#password-modal').open) $('#password-modal').showModal();
  document.querySelectorAll('.needs-user').forEach(b=>b.disabled=true);
  document.querySelectorAll('.admin-only').forEach(el=>el.hidden=true);
  $('#password-fields input').focus();
}
function formatField() {
  const label = document.createElement('label');
  label.textContent = 'Формат файла';
  const select = document.createElement('select');
  select.name = 'format';
  select.required = true;
  for (const format of ['JSON', 'CSV', 'XML']) {
    const option = document.createElement('option');
    option.value = format.toLowerCase();
    option.textContent = format;
    select.append(option);
  }
  label.append(select);
  return label;
}
async function downloadExport(format) {
  const response = await fetch('/api', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({action: 'export', format})
  });
  if (!response.ok) {
    const data = await response.json();
    if (data.ended) endScreen(data.error);
    throw new Error(data.error || 'Не удалось выгрузить данные.');
  }
  const file = await response.blob();
  const url = URL.createObjectURL(file);
  const link = document.createElement('a');
  link.href = url;
  link.download = `kontur-users.${format}`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}
function exportDialog() {
  openDialog('Выгрузка учётных данных', 'Выберите формат. Файл содержит имена, параметры и хеши паролей. Открытые пароли не хранятся и восстановить их нельзя.', [formatField()], async values => {
    await downloadExport(values.format);
    $('#modal').close();
    toast('Файл подготовлен к скачиванию.');
  }, 'Скачать файл');
}
function rekeyDialog(){openDialog('Смена парольной фразы','Введите текущую фразу, затем новую и её подтверждение.',[field('Текущая парольная фраза','oldPhrase','password','current-password'),field('Новая парольная фраза','newPhrase'),field('Повторите новую фразу','confirmation')],async values=>{await api('rekey',values);$('#modal').close();toast('Парольная фраза изменена. Используйте её при следующем запуске.');},'Изменить фразу');}
function addDialog() {openDialog('Новый пользователь','Создайте уникальное имя. Пользователь установит пароль при первом входе.',[field('Имя пользователя','name','text','off')],async values=>{await api('add',values);$('#modal').close();await loadUsers();toast('Пользователь добавлен с пустым паролем.');},'Добавить');}
function checkbox(text,name,checked,disabled=false) {const label=document.createElement('label');label.className='check';const input=document.createElement('input');input.type='checkbox';input.name=name;input.checked=checked;input.disabled=disabled;label.append(input,document.createTextNode(text));return label;}
function editDialog(account) {openDialog(`Доступ: ${account.name}`,'Ограничение проверяется при установке и смене пароля.',[checkbox('Заблокировать учётную запись','blocked',account.blocked,account.name==='ADMIN'),checkbox('Требовать латинские и кириллические буквы','restricted',account.restricted)],async()=>{
  await api('update',{name:account.name,blocked:$('#dialog-fields [name=blocked]').checked,restricted:$('#dialog-fields [name=restricted]').checked});
  if(account.name===user.name)user=(await api('state')).user;
  $('#modal').close();await render();toast('Параметры доступа сохранены.');
});}
function about(){openDialog('О программе','Контур · Разграничение полномочий пользователей',[],null);const p=document.createElement('p');p.className='about-copy';p.textContent='Автор: Желтов Данила, группа ИДБ-23-11.\n\nИндивидуальное задание: защита файла учётных данных. Используются потоковый шифр RC4 и хеш-функция MD2 для получения ключа без соли; временный файл восстанавливается после аварийного завершения.\n\nОграничение на пароль: наличие латинских букв и символов кириллицы. Проверяется наличие хотя бы одной буквы A–Z или a–z и одной кириллической буквы.\n\nРежимы работы: администратор ADMIN и обычный пользователь. Реализация: Go, локальный веб-интерфейс.';$('#dialog-fields').append(p);}
async function loadUsers(){const data=await api('list');const users=data.users;$('#count').textContent=`Всего: ${users.length}`;$('#users').replaceChildren(...users.map(account=>{
 const row=document.createElement('tr');const cell=(text)=>{const td=document.createElement('td');td.textContent=text;row.append(td);return td;};cell(account.name);
 const status=cell('');const badge=document.createElement('span');badge.className=`badge ${account.blocked?'red':'green'}`;badge.textContent=account.blocked?'Заблокирован':'Разрешён';status.append(badge);
 cell(account.restricted?'Включены':'Отключены');cell(account.initial?'Не установлен':'Установлен');const actions=cell('');const button=document.createElement('button');button.textContent='Настроить';button.setAttribute('aria-label',`Настроить доступ: ${account.name}`);button.addEventListener('click',()=>editDialog(account));actions.append(button);return row;
}));}
async function render(){
 $('#login').hidden=!!user;$('#workspace').hidden=!user||user.initial;document.querySelectorAll('.needs-user').forEach(b=>b.disabled=!user||user.initial);document.querySelectorAll('.admin-only').forEach(el=>el.hidden=!user||user.name!=='ADMIN'||user.initial);
 if(!user){$('#role').textContent='Локальная сессия';return;}
 $('#role').textContent=user.name==='ADMIN'?'Администратор':'Пользователь';
 if(user.initial){showPasswordScreen(true);return;}
 $('#welcome').textContent=user.name==='ADMIN'?'Управление доступом':`Здравствуйте, ${user.name}`;$('#workspace-label').textContent=user.name==='ADMIN'?'ПАНЕЛЬ АДМИНИСТРАТОРА':'ЛИЧНЫЙ КАБИНЕТ';$('#workspace-description').textContent=user.name==='ADMIN'?'Управляйте пользователями и правилами их работы.':'Здесь вы можете изменить пароль своей учётной записи.';$('#account-name').textContent=user.name;$('#policy').textContent=user.restricted?'Ограничения включены':'Ограничения отключены';
 if(user.name==='ADMIN')await loadUsers();
}
$('#login-form').addEventListener('submit',async event=>{event.preventDefault();const button=$('#login-form button[type=submit]');button.disabled=true;$('#login-form .error').textContent='';try{const values=Object.fromEntries(new FormData(event.currentTarget));const data=await api('login',values);event.target.reset();resetPasswords(event.target);user=data.user;await render();}catch(e){$('#login-form .error').textContent=message(e);}finally{button.disabled=false;}});
$('#dialog-form').addEventListener('submit',async event=>{event.preventDefault();if(!submitAction)return;const button=$('#submit-modal');button.disabled=true;$('#dialog-form .error').textContent='';try{await submitAction(Object.fromEntries(new FormData(event.currentTarget)));}catch(e){$('#dialog-form .error').textContent=message(e);}finally{button.disabled=false;}});
$('#password-form').addEventListener('submit',async event=>{event.preventDefault();const button=$('#submit-password');if(button.disabled)return;button.disabled=true;$('#cancel-password').disabled=true;$('#password-form .error').textContent='';try{const values=Object.fromEntries(new FormData(event.currentTarget));const data=await api('password',{old:'',...values});user=data.user;clearPasswordView();await render();toast('Пароль сохранён.');}catch(e){$('#password-form .error').textContent=message(e);}finally{button.disabled=false;$('#cancel-password').disabled=false;}});
$('#cancel-password').addEventListener('click',async()=>{if(requiredPassword){await exitProgram();return;}clearPasswordView();await render();});
async function exitProgram(){try{await api('exit');endScreen();}catch(e){toast(message(e));}}
$('#exit-login').addEventListener('click',exitProgram);
$('#password-modal').addEventListener('cancel',event=>{if(requiredPassword){event.preventDefault();exitProgram();}});
function cancelDialog(){$('#modal').close();}
$('#cancel-modal').addEventListener('click',cancelDialog);$('#close-modal').addEventListener('click',cancelDialog);
$('#modal').addEventListener('close',()=>{$('#dialog-fields').replaceChildren();submitAction=null;});
document.querySelectorAll('[data-command]').forEach(button=>button.addEventListener('click',async()=>{document.querySelectorAll('details').forEach(el=>el.open=false);try{switch(button.dataset.command){case 'about':about();break;case 'logout':await logout();break;case 'exit':await exitProgram();break;case 'password':showPasswordScreen();break;case 'add':addDialog();break;case 'export':exportDialog();break;case 'rekey':rekeyDialog();break;}}catch(e){$('#page-error').textContent=message(e);}}));
enhancePasswords(document);
setupMenus();
api('state').then(async data=>{user=data.user;await render();}).catch(e=>{$('#login-form .error').textContent=message(e);});
