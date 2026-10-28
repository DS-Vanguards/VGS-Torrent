(function () {
  "use strict";

  const VGS = window.VGS || {};
  const state = {
    sections: [],
    items: [],
    tab: "",
    users: [],
    assignableRoles: VGS.roles || [],
    roleUserId: null,
    pickedRole: "",
    dividers: [],
    seenIp: VGS.seenIp || "",
  };

  const $ = (id) => document.getElementById(id);

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function showToast(message) {
    const toast = $("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    clearTimeout(showToast._timer);
    showToast._timer = setTimeout(() => toast.classList.remove("show"), 2800);
  }

  async function request(url, options) {
    const response = await fetch(url, options || {});
    let data = {};
    try {
      data = await response.json();
    } catch (err) {
      data = {};
    }
    if (!response.ok) {
      const error = new Error(data.erro || "Não foi possível concluir.");
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function roleLabel(role) {
    return (VGS.roleLabels && VGS.roleLabels[role]) || role;
  }

  function openModal(id) {
    const modal = $(id);
    if (modal) modal.classList.add("open");
  }

  function closeModal(id) {
    const modal = $(id);
    if (modal) modal.classList.remove("open");
  }

  function tabButton(section) {
    const active = String(section.id) === String(state.tab);
    return `<button class="nav-tab${active ? " active" : ""}" data-tab="${section.id}" type="button" title="${escapeHtml(section.title)}">
      <span class="tab-icon">${escapeHtml(section.icon || "💾")}</span>
      <span class="nav-label">${escapeHtml(section.title)}</span>
    </button>`;
  }

  function renderNav() {
    const nav = $("main-nav");
    if (!nav) return;
    const marks = [
      ...state.sections.map((section) => ({
        kind: "tab",
        order: Number(section.sort_order) || 0,
        section,
      })),
      ...state.dividers.map((divider) => ({
        kind: "div",
        order: Number(divider.sort_order) || 0,
        divider,
      })),
    ];
    marks.sort((a, b) => a.order - b.order || (a.kind === "div" ? -1 : 1));
    const html = marks
      .map((mark) => {
        if (mark.kind === "div") {
          return `<div class="nav-divider" title="${escapeHtml(mark.divider.title)}"><span class="nav-divider-label">${escapeHtml(mark.divider.title)}</span></div>`;
        }
        return tabButton(mark.section);
      })
      .join("");
    const admin = VGS.isAdmin
      ? `<button class="nav-tab${state.tab === "admin" ? " active" : ""}" data-tab="admin" type="button" title="Administração"><span class="tab-icon">⚙</span><span class="nav-label">Administração</span></button>`
      : "";
    nav.innerHTML = html + admin;
  }

  function renderItems() {
    const grid = $("item-grid");
    const section = state.sections.find((row) => String(row.id) === String(state.tab));
    $("tab-label").textContent = section ? section.title.toUpperCase() : "ACERVO";
    $("section-lead").textContent = section ? section.description || "" : "";
    const addBtn = $("btn-add-item");
    if (addBtn) addBtn.hidden = !section;
    if (!grid) return;
    if (!section) {
      grid.innerHTML = `<div class="empty-card">Nenhuma aba disponível para o seu cargo.</div>`;
      return;
    }
    if (!state.items.length) {
      grid.innerHTML = `<div class="empty-card">Nenhum download ou tutorial nesta aba ainda.</div>`;
      return;
    }
    grid.innerHTML = state.items
      .map((item) => {
        const actions = VGS.canEdit
          ? `<div class="card-actions">
              <button class="btn-sm btn-save-role" type="button" data-edit-item="${item.id}">Editar</button>
              <button class="btn-sm btn-danger" type="button" data-del-item="${item.id}">Excluir</button>
            </div>`
          : "";
        const locked = !!item.locked;
        const openLabel = item.kind === "tutorial" ? "TUTORIAL" : "DOWNLOAD";
        const open = locked
          ? `<button class="save-btn card-open" type="button" data-locked-tier="${escapeHtml(item.tier_label || "VIP")}">ABRIR ${openLabel}</button>`
          : item.kind === "tutorial" && item.body
            ? `<button class="save-btn card-open" type="button" data-open-tutorial="${item.id}">ABRIR TUTORIAL</button>`
            : item.url
              ? `<a class="save-btn card-open" href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">ABRIR ${openLabel}</a>`
              : "";
        return `<article class="download-card">
          <div class="card-top">
            <span class="badge badge-${escapeHtml(item.kind)}">${escapeHtml(item.kind_label)}</span>
            <span class="badge badge-tier">${escapeHtml(item.tier_label)}</span>
          </div>
          <h2>${escapeHtml(item.title)}</h2>
          <p>${escapeHtml(item.description || "")}</p>
          ${open}
          ${actions}
        </article>`;
      })
      .join("");
  }

  async function loadSections(preferred) {
    const data = await request("/api/secoes");
    state.sections = data.secoes || [];
    state.dividers = data.divisoes || [];
    if (preferred && (preferred === "admin" || state.sections.some((row) => String(row.id) === String(preferred)))) {
      state.tab = preferred;
    } else if (!state.sections.some((row) => String(row.id) === String(state.tab)) && state.tab !== "admin") {
      state.tab = state.sections.length ? String(state.sections[0].id) : (VGS.isAdmin ? "admin" : "");
    }
    renderNav();
    if (state.tab === "admin") {
      showAdmin();
    } else {
      showLibrary();
      if (state.tab) await loadItems(state.tab);
      else renderItems();
    }
    if (VGS.isAdmin && state.tab === "admin") {
      await loadAdminTables();
    }
  }

  async function loadItems(sectionId) {
    const data = await request(`/api/secoes/${sectionId}/itens`);
    state.items = data.itens || [];
    renderItems();
  }

  function showLibrary() {
    $("view-library").classList.add("active");
    const admin = $("view-admin");
    if (admin) admin.classList.remove("active");
  }

  function showAdmin() {
    $("view-library").classList.remove("active");
    const admin = $("view-admin");
    if (admin) admin.classList.add("active");
  }

  function fillSectionSelect(selected) {
    const select = $("item-section");
    if (!select) return;
    select.innerHTML = state.sections
      .map((section) => `<option value="${section.id}">${escapeHtml(section.title)}</option>`)
      .join("");
    if (selected) select.value = String(selected);
  }

  function syncTutorialFields() {
    const wrap = $("item-body-wrap");
    if (!wrap) return;
    wrap.hidden = $("item-kind").value !== "tutorial";
  }

  function openItemModal(item) {
    fillSectionSelect(item ? item.section_id : state.tab);
    $("item-id").value = item ? item.id : "";
    $("item-title").value = item ? item.title : "";
    $("item-kind").value = item ? item.kind : "download";
    $("item-tier").value = item ? item.tier_override || "" : "";
    $("item-description").value = item ? item.description || "" : "";
    $("item-url").value = item ? item.url || "" : "";
    $("item-body").value = item ? item.body || "" : "";
    $("item-order").value = item ? item.sort_order || 0 : 0;
    $("item-modal-title").textContent = item ? "Editar botão" : "Novo botão";
    syncTutorialFields();
    openModal("item-modal");
  }

  function openSectionModal(section) {
    $("section-id").value = section ? section.id : "";
    $("section-title").value = section ? section.title : "";
    $("section-icon").value = section ? section.icon || "💾" : "💾";
    $("section-tier").value = section ? section.tier : "basico";
    $("section-description").value = section ? section.description || "" : "";
    $("section-order").value = section ? section.sort_order || 0 : (state.sections.length + 1) * 10;
    $("section-modal-title").textContent = section ? "Editar aba" : "Nova aba";
    openModal("section-modal");
  }

  function showTierLock(label) {
    const text = $("tier-modal-text");
    if (text) text.textContent = `Você não possui acesso ${label || "VIP"}`;
    openModal("tier-modal");
  }

  function openTutorial(item) {
    if (item.locked) {
      showTierLock(item.tier_label);
      return;
    }
    $("tutorial-title").textContent = item.title;
    $("tutorial-body").textContent = item.body || item.description || "";
    const link = $("tutorial-link");
    if (item.url) {
      link.href = item.url;
      link.hidden = false;
    } else {
      link.hidden = true;
      link.removeAttribute("href");
    }
    openModal("tutorial-modal");
  }

  async function saveItem(event) {
    event.preventDefault();
    const id = $("item-id").value;
    const payload = {
      section_id: Number($("item-section").value),
      title: $("item-title").value.trim(),
      kind: $("item-kind").value,
      tier: $("item-tier").value,
      description: $("item-description").value.trim(),
      url: $("item-url").value.trim(),
      body: $("item-body").value.trim(),
      sort_order: Number($("item-order").value || 0),
    };
    try {
      if (id) {
        await request(`/api/itens/${id}`, { method: "PUT", body: JSON.stringify(payload) });
      } else {
        await request("/api/itens", { method: "POST", body: JSON.stringify(payload) });
      }
      closeModal("item-modal");
      showToast("✔ Botão salvo");
      await loadSections(String(payload.section_id));
    } catch (err) {
      showToast("✘ " + err.message);
    }
  }

  async function saveSection(event) {
    event.preventDefault();
    const id = $("section-id").value;
    const payload = {
      title: $("section-title").value.trim(),
      icon: $("section-icon").value.trim() || "💾",
      tier: $("section-tier").value,
      description: $("section-description").value.trim(),
      sort_order: Number($("section-order").value || 0),
    };
    try {
      let savedId = id;
      if (id) {
        await request(`/api/secoes/${id}`, { method: "PUT", body: JSON.stringify(payload) });
      } else {
        const data = await request("/api/secoes", { method: "POST", body: JSON.stringify(payload) });
        savedId = data.secao && data.secao.id;
      }
      closeModal("section-modal");
      showToast("✔ Aba salva");
      await loadSections(savedId ? String(savedId) : "admin");
      if (state.tab === "admin") renderSections();
    } catch (err) {
      showToast("✘ " + err.message);
    }
  }

  function renderSections() {
    const body = $("sections-body");
    if (!body) return;
    if (!state.sections.length) {
      body.innerHTML = `<tr><td colspan="5" class="empty">Nenhuma aba.</td></tr>`;
      return;
    }
    body.innerHTML = state.sections
      .map(
        (section) => `<tr>
          <td><strong>${escapeHtml(section.icon)} ${escapeHtml(section.title)}</strong></td>
          <td><span class="badge badge-tier">${escapeHtml(section.tier_label)}</span></td>
          <td>${Number(section.item_count) || 0}</td>
          <td>${Number(section.sort_order) || 0}</td>
          <td>
            <div class="actions-stack">
              <button class="btn-sm btn-save-role" type="button" data-edit-section="${section.id}">Editar</button>
              <button class="btn-sm btn-danger" type="button" data-del-section="${section.id}">Excluir</button>
            </div>
          </td>
        </tr>`
      )
      .join("");
  }

  async function loadUsers() {
    const data = await request("/api/usuarios");
    const body = $("users-body");
    if (!body) return;
    state.users = data.usuarios || [];
    state.assignableRoles = data.assignable_roles || [];
    if (!state.users.length) {
      body.innerHTML = `<tr><td colspan="4" class="empty">Nenhum usuário.</td></tr>`;
      return;
    }
    body.innerHTML = state.users
      .map((user) => {
        const pending = user.must_reset_password ? `<span class="badge badge-yellow">Aguardando senha</span>` : "";
        const primary = user.is_primary ? `<span class="text-muted">Conta padrão</span>` : "";
        let cargo = `<span class="badge badge-${escapeHtml(user.role)}">${escapeHtml(roleLabel(user.role))}</span>`;
        if (user.is_primary) cargo += primary;
        else if (user.is_self) cargo += `<span class="text-muted">Sua conta</span>`;
        else if (user.can_edit_role) {
          cargo += `<button class="btn-sm btn-save-role" data-edit-role="${user.id}" type="button">Alterar cargo</button>`;
        }
        const resetBtn = user.can_reset
          ? `<button class="btn-sm btn-warning" data-reset="${user.id}" type="button">Redefinir senha</button>`
          : "";
        const delBtn = user.can_manage
          ? `<button class="btn-sm btn-danger" data-del-user="${user.id}" type="button">Excluir conta</button>`
          : "";
        return `<tr>
          <td><strong>${escapeHtml(user.username)}</strong> ${pending}</td>
          <td>${escapeHtml(user.email)}</td>
          <td><div class="cargo-cell">${cargo}</div></td>
          <td><div class="actions-stack">${resetBtn}${delBtn}</div></td>
        </tr>`;
      })
      .join("");
  }

  function openRoleModal(userId) {
    const user = state.users.find((item) => String(item.id) === String(userId));
    if (!user) return;
    state.roleUserId = user.id;
    state.pickedRole = user.role;
    $("role-user-label").textContent = `${user.username} · ${user.email}`;
    const roles = [...new Set([user.role, ...(state.assignableRoles || [])])];
    $("role-options").innerHTML = roles
      .map(
        (role) => `<button class="role-option${role === user.role ? " selected" : ""}" type="button" data-pick-role="${role}">
          <span class="badge badge-${role}">${escapeHtml(roleLabel(role))}</span>
          <span class="role-check">✓</span>
        </button>`
      )
      .join("");
    openModal("role-modal");
  }

  async function saveRole() {
    if (!state.roleUserId || !state.pickedRole) return;
    try {
      await request(`/api/usuarios/${state.roleUserId}/cargo`, {
        method: "POST",
        body: JSON.stringify({ role: state.pickedRole }),
      });
      showToast("✔ Cargo atualizado");
      closeModal("role-modal");
      await loadUsers();
    } catch (err) {
      showToast("✘ " + err.message);
    }
  }

  async function loadBlocks() {
    const body = $("blocks-body");
    if (!body) return;
    try {
      const seen = await request("/api/meu-ip");
      state.seenIp = seen.ip || state.seenIp;
      const label = $("seen-ip");
      if (label && state.seenIp) label.textContent = state.seenIp;
    } catch (err) {}
    const data = await request("/api/bloqueios");
    const rows = data.bloqueios || [];
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="5" class="empty">Nenhuma máquina bloqueada.</td></tr>`;
      return;
    }
    body.innerHTML = rows
      .map(
        (row) => `<tr>
          <td style="font-family:var(--mono);font-size:11px">${escapeHtml(row.token)}</td>
          <td>${escapeHtml(row.ip)}</td>
          <td><span class="badge ${row.manual || row.strike_level >= 6 ? "badge-danger" : "badge-yellow"}">${escapeHtml(row.level_label)}</span></td>
          <td>${escapeHtml(row.blocked_until)}</td>
          <td>
            <div class="actions-stack">
              <button class="btn-sm btn-warning" data-reduce="${row.id}" type="button">Alterar bloqueio</button>
              <button class="btn-sm btn-danger" data-unblock="${row.id}" type="button">Remover bloqueio</button>
            </div>
          </td>
        </tr>`
      )
      .join("");
  }

  function renderAccess(data) {
    const panel = $("access-panel");
    if (!panel) return;
    const sections = data.secoes || [];
    const roles = data.cargos || [];
    if (!roles.length) {
      panel.innerHTML = `<p class="admin-hint">Nenhum cargo configurável.</p>`;
      return;
    }
    panel.innerHTML = roles
      .map((role) => {
        const selected = new Set((role.section_ids || []).map(String));
        const boxes = sections.length
          ? sections
              .map(
                (section) => `<label class="check-row">
                  <input type="checkbox" data-access-role="${escapeHtml(role.role)}" data-access-section="${section.id}"${selected.has(String(section.id)) ? " checked" : ""}>
                  <span>${escapeHtml(section.icon)} ${escapeHtml(section.title)}</span>
                </label>`
              )
              .join("")
          : `<span class="text-muted">Nenhuma aba criada.</span>`;
        return `<section class="access-card" data-role-card="${escapeHtml(role.role)}">
          <h3>${escapeHtml(role.label)}</h3>
          <div class="access-grid">${boxes}</div>
        </section>`;
      })
      .join("");
  }

  async function loadAccess() {
    if (!$("access-panel")) return;
    const data = await request("/api/acessos");
    renderAccess(data);
  }

  async function saveAccess(role) {
    const boxes = [...document.querySelectorAll("[data-access-role]")].filter(
      (box) => box.dataset.accessRole === role
    );
    const sectionIds = boxes.filter((box) => box.checked).map((box) => Number(box.dataset.accessSection));
    await request("/api/acessos", {
      method: "PUT",
      body: JSON.stringify({ role, section_ids: sectionIds }),
    });
  }

  function renderDividers() {
    const body = $("dividers-body");
    if (!body) return;
    if (!state.dividers.length) {
      body.innerHTML = `<tr><td colspan="3" class="empty">Nenhuma divisão. As abas ficam em sequência.</td></tr>`;
      return;
    }
    body.innerHTML = state.dividers
      .map(
        (divider) => `<tr>
          <td><strong>${escapeHtml(divider.title)}</strong></td>
          <td>${Number(divider.sort_order) || 0}</td>
          <td>
            <div class="actions-stack">
              <button class="btn-sm btn-save-role" type="button" data-edit-divider="${divider.id}">Editar</button>
              <button class="btn-sm btn-danger" type="button" data-del-divider="${divider.id}">Excluir</button>
            </div>
          </td>
        </tr>`
      )
      .join("");
  }

  function openDividerModal(divider) {
    $("divider-id").value = divider ? divider.id : "";
    $("divider-title").value = divider ? divider.title : "";
    $("divider-order").value = divider ? divider.sort_order || 0 : 15;
    $("divider-modal-title").textContent = divider ? "Editar divisão" : "Nova divisão";
    openModal("divider-modal");
  }

  async function loadAdminTables() {
    renderSections();
    renderDividers();
    await loadAccess();
    await loadUsers();
    await loadBlocks();
  }

  document.addEventListener("click", async (event) => {
    const lockedBtn = event.target.closest("[data-locked-tier]");
    if (lockedBtn) {
      event.preventDefault();
      showTierLock(lockedBtn.dataset.lockedTier);
      return;
    }

    const tabBtn = event.target.closest("[data-tab]");
    if (tabBtn && tabBtn.closest("#main-nav")) {
      state.tab = tabBtn.dataset.tab;
      renderNav();
      if (state.tab === "admin") {
        showAdmin();
        try {
          await loadAdminTables();
        } catch (err) {
          showToast("✘ " + err.message);
        }
      } else {
        showLibrary();
        try {
          await loadItems(state.tab);
        } catch (err) {
          showToast("✘ " + err.message);
        }
      }
      return;
    }

    const closer = event.target.closest("[data-close]");
    if (closer) {
      closeModal(closer.dataset.close);
      return;
    }

    const tutorialBtn = event.target.closest("[data-open-tutorial]");
    if (tutorialBtn) {
      const item = state.items.find((row) => String(row.id) === tutorialBtn.dataset.openTutorial);
      if (item) openTutorial(item);
      return;
    }

    if (event.target.closest("#btn-add-item")) {
      if (!state.sections.length) {
        showToast("✘ Crie uma aba antes do botão");
        return;
      }
      openItemModal(null);
      return;
    }
    if (event.target.closest("#btn-add-section")) {
      openSectionModal(null);
      return;
    }
    if (event.target.closest("#btn-add-block")) {
      const form = $("manual-block-form");
      if (form) form.reset();
      const time = $("manual-time-wrap");
      if (time) time.hidden = false;
      if ($("manual-ip") && state.seenIp) $("manual-ip").value = state.seenIp;
      openModal("manual-block-modal");
      return;
    }
    if (event.target.closest("#btn-add-divider")) {
      openDividerModal(null);
      return;
    }
    if (event.target.closest("#btn-add-user")) {
      const form = $("user-form");
      if (form) form.reset();
      const role = $("u-role");
      if (role) {
        const hasVisitor = Array.from(role.options).some((opt) => opt.value === "visitante");
        role.value = hasVisitor ? "visitante" : role.options[0] ? role.options[0].value : "";
      }
      openModal("user-modal");
      return;
    }

    const editItem = event.target.closest("[data-edit-item]");
    if (editItem) {
      const item = state.items.find((row) => String(row.id) === editItem.dataset.editItem);
      if (item) openItemModal(item);
      return;
    }
    const delItem = event.target.closest("[data-del-item]");
    if (delItem) {
      if (!confirm("Excluir este botão?")) return;
      try {
        await request(`/api/itens/${delItem.dataset.delItem}`, { method: "DELETE" });
        showToast("✔ Botão excluído");
        await loadSections(state.tab);
      } catch (err) {
        showToast("✘ " + err.message);
      }
      return;
    }
    const editSection = event.target.closest("[data-edit-section]");
    if (editSection) {
      const section = state.sections.find((row) => String(row.id) === editSection.dataset.editSection);
      if (section) openSectionModal(section);
      return;
    }
    const delSection = event.target.closest("[data-del-section]");
    if (delSection) {
      if (!confirm("Excluir esta aba e todos os botões dela?")) return;
      try {
        await request(`/api/secoes/${delSection.dataset.delSection}`, { method: "DELETE" });
        showToast("✔ Aba excluída");
        state.tab = "admin";
        await loadSections("admin");
        renderSections();
      } catch (err) {
        showToast("✘ " + err.message);
      }
      return;
    }
    const editDivider = event.target.closest("[data-edit-divider]");
    if (editDivider) {
      const divider = state.dividers.find((row) => String(row.id) === editDivider.dataset.editDivider);
      if (divider) openDividerModal(divider);
      return;
    }
    const delDivider = event.target.closest("[data-del-divider]");
    if (delDivider) {
      if (!confirm("Excluir esta divisão?")) return;
      try {
        await request(`/api/divisoes/${delDivider.dataset.delDivider}`, { method: "DELETE" });
        showToast("✔ Divisão excluída");
        await loadSections("admin");
      } catch (err) {
        showToast("✘ " + err.message);
      }
      return;
    }
    const editRole = event.target.closest("[data-edit-role]");
    if (editRole) {
      openRoleModal(editRole.dataset.editRole);
      return;
    }
    const pick = event.target.closest("[data-pick-role]");
    if (pick) {
      state.pickedRole = pick.dataset.pickRole;
      document.querySelectorAll(".role-option").forEach((btn) => {
        btn.classList.toggle("selected", btn.dataset.pickRole === state.pickedRole);
      });
      return;
    }
    if (event.target.closest("#role-modal-save")) {
      saveRole();
      return;
    }
    const reset = event.target.closest("[data-reset]");
    if (reset) {
      if (!confirm("Redefinir a senha deste usuário? Ele poderá entrar só com o usuário/e-mail e criar uma senha nova.")) return;
      try {
        await request(`/api/usuarios/${reset.dataset.reset}/redefinir-senha`, { method: "POST" });
        showToast("✔ Senha redefinida. O usuário entra sem senha e cria uma nova.");
        await loadUsers();
      } catch (err) {
        showToast("✘ " + err.message);
      }
      return;
    }
    const delUser = event.target.closest("[data-del-user]");
    if (delUser) {
      if (!confirm("Excluir esta conta permanentemente?")) return;
      try {
        await request(`/api/usuarios/${delUser.dataset.delUser}`, { method: "DELETE" });
        showToast("✔ Conta excluída");
        await loadUsers();
      } catch (err) {
        showToast("✘ " + err.message);
      }
      return;
    }
    const reduce = event.target.closest("[data-reduce]");
    if (reduce) {
      $("block-id").value = reduce.dataset.reduce;
      $("block-form").reset();
      $("block-id").value = reduce.dataset.reduce;
      openModal("block-modal");
      return;
    }
    const unblock = event.target.closest("[data-unblock]");
    if (unblock) {
      if (!confirm("Remover o bloqueio desta máquina?")) return;
      try {
        await request(`/api/bloqueios/${unblock.dataset.unblock}`, { method: "DELETE" });
        showToast("✔ Bloqueio removido");
        await loadBlocks();
      } catch (err) {
        showToast("✘ " + err.message);
      }
    }
  });

  document.addEventListener("submit", async (event) => {
    if (event.target.id === "item-form") return saveItem(event);
    if (event.target.id === "section-form") return saveSection(event);
    if (event.target.id === "user-form") {
      event.preventDefault();
      try {
        await request("/api/usuarios", {
          method: "POST",
          body: JSON.stringify({
            username: $("u-username").value.trim(),
            email: $("u-email").value.trim(),
            password: $("u-password").value,
            confirm_password: $("u-confirm").value,
            role: $("u-role").value,
          }),
        });
        showToast("✔ Usuário adicionado");
        closeModal("user-modal");
        await loadUsers();
      } catch (err) {
        showToast("✘ " + err.message);
      }
      return;
    }
    if (event.target.id === "block-form") {
      event.preventDefault();
      try {
        await request(`/api/bloqueios/${$("block-id").value}/tempo`, {
          method: "POST",
          body: JSON.stringify({
            amount: $("block-amount").value,
            unit: $("block-unit").value,
          }),
        });
        showToast("✔ Bloqueio atualizado");
        closeModal("block-modal");
        await loadBlocks();
      } catch (err) {
        showToast("✘ " + err.message);
      }
      return;
    }
    if (event.target.id === "manual-block-form") {
      event.preventDefault();
      const permanent = $("manual-permanent").checked;
      try {
        await request("/api/bloqueios", {
          method: "POST",
          body: JSON.stringify({
            ip: $("manual-ip").value.trim(),
            permanent,
            amount: permanent ? null : $("manual-amount").value,
            unit: $("manual-unit").value,
          }),
        });
        showToast("✔ Máquina bloqueada");
        closeModal("manual-block-modal");
        await loadBlocks();
      } catch (err) {
        showToast("✘ " + err.message);
      }
      return;
    }
    if (event.target.id === "divider-form") {
      event.preventDefault();
      const id = $("divider-id").value;
      const payload = {
        title: $("divider-title").value.trim(),
        sort_order: Number($("divider-order").value || 0),
      };
      try {
        if (id) {
          await request(`/api/divisoes/${id}`, { method: "PUT", body: JSON.stringify(payload) });
        } else {
          await request("/api/divisoes", { method: "POST", body: JSON.stringify(payload) });
        }
        showToast("✔ Divisão salva");
        closeModal("divider-modal");
        await loadSections("admin");
      } catch (err) {
        showToast("✘ " + err.message);
      }
    }
  });

  const kind = $("item-kind");
  if (kind) kind.addEventListener("change", syncTutorialFields);

  document.addEventListener("change", async (event) => {
    if (event.target.id === "manual-permanent") {
      const time = $("manual-time-wrap");
      if (time) time.hidden = event.target.checked;
      return;
    }
    const box = event.target.closest("[data-access-role]");
    if (!box) return;
    try {
      await saveAccess(box.dataset.accessRole);
      showToast("✔ Canais atualizados");
    } catch (err) {
      showToast("✘ " + err.message);
      loadAccess().catch(() => {});
    }
  });

  const collapse = $("sidebar-collapse");
  if (collapse) {
    const syncLabel = () => {
      const mini = document.documentElement.classList.contains("side-mini");
      const text = mini ? "Expandir menu" : "Recolher menu";
      collapse.setAttribute("aria-label", text);
      const label = collapse.querySelector(".collapse-label");
      if (label) label.textContent = text;
    };
    syncLabel();
    collapse.addEventListener("click", () => {
      const mini = document.documentElement.classList.toggle("side-mini");
      try {
        localStorage.setItem("vgs-side", mini ? "mini" : "full");
      } catch (err) {}
      syncLabel();
    });
  }

  loadSections().catch((err) => showToast("✘ " + err.message));
})();
