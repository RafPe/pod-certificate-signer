export function versionDestination(version, currentPath, currentBase) {
  const prefix = currentBase.replace(/\/$/, '') + '/';
  const route = currentPath.startsWith(prefix) ? currentPath.slice(prefix.length) : '';
  const target = version.routes.includes(route) ? route : version.routes.includes('getting-started/') ? 'getting-started/' : '';
  return version.base.replace(/\/$/, '') + '/' + target;
}

export function menuVersions(versions, current, expanded = false) {
  const releases = versions.filter(version => /^v\d+\.\d+\.\d+$/.test(version.id)).sort((a,b) => {
    const left = a.id.slice(1).split('.').map(Number), right = b.id.slice(1).split('.').map(Number);
    return right[0]-left[0] || right[1]-left[1] || right[2]-left[2];
  });
  const choices = [...versions.filter(version => version.id === 'current'),...(expanded ? releases : releases.slice(0,3))];
  const selected = versions.find(version => version.id === current);
  if(selected && !choices.some(version => version.id === current)) choices.push({...selected,label:`${selected.label} (archived)`,disabled:true});
  return choices;
}

if (typeof document !== 'undefined') {
  for (const select of document.querySelectorAll('[data-docs-version]')) {
    const root = select.dataset.root.replace(/\/$/, '');
    fetch(`${root}/docs-versions.json`).then(response => {
      if (!response.ok) throw new Error('Version list is unavailable.');
      return response.json();
    }).then(({versions}) => {
      if (!versions.length) return;
      let expanded = false;
      function renderOptions() {
        select.replaceChildren(...menuVersions(versions,select.dataset.current,expanded).map(version => {
          const option = document.createElement('option');
          option.value = version.id;
          option.disabled = Boolean(version.disabled);
          option.textContent = version.label;
          option.selected = version.id === select.dataset.current;
          return option;
        }));
        const toggle = document.createElement('option');
        toggle.value = '__toggle_versions__';
        toggle.textContent = expanded ? 'Recent versions' : 'All versions';
        select.append(toggle);
        select.dataset.expanded = String(expanded);
      }
      renderOptions();
      select.addEventListener('change', () => {
        if (select.value === '__toggle_versions__') {
          expanded = !expanded;
          renderOptions();
          select.focus();
          // Native pickers require user activation. Keyboard and test events can omit it.
          try { select.showPicker?.(); } catch {}
          return;
        }
        const version = versions.find(version => version.id === select.value);
        if (version) location.assign(versionDestination(version,location.pathname,select.dataset.base));
      });
    }).catch(() => {
      select.title = 'Only the current documentation is available.';
    });
  }
}
