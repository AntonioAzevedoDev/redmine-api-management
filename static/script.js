document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('select_all').onclick = function() {
        var checkboxes = document.querySelectorAll('input[name="selected_entries"]');
        for (var checkbox of checkboxes) {
            checkbox.checked = this.checked;
        }
        toggleSelectedActions();
    }

    var checkboxes = document.querySelectorAll('input[name="selected_entries"]');
    for (var checkbox of checkboxes) {
        checkbox.onclick = toggleSelectedActions;
    }

    async function submitForm(actionType) {
    const form = document.getElementById('time_entries_form');
    form.setAttribute('target', '_blank');

    // Adiciona ou atualiza o campo "tipo"
    let tipoInput = form.querySelector('input[name="tipo"]');
    if (!tipoInput) {
        tipoInput = document.createElement('input');
        tipoInput.setAttribute('type', 'hidden');
        tipoInput.setAttribute('name', 'tipo');
        form.appendChild(tipoInput);
    }
    tipoInput.value = actionType;

    // Coleta entradas selecionadas
    const selectedEntries = Array.from(document.querySelectorAll('input[name="selected_entries"]:checked')).map(cb => cb.value);

    let selectedEntriesInput = form.querySelector('input[name="selected_entries"]');
    if (!selectedEntriesInput) {
        selectedEntriesInput = document.createElement('input');
        selectedEntriesInput.setAttribute('type', 'hidden');
        selectedEntriesInput.setAttribute('name', 'selected_entries');
        form.appendChild(selectedEntriesInput);
    }
    selectedEntriesInput.value = selectedEntries.join(',');

    // Obtém o token da URL atual ou gera um novo se necessário
    const urlParams = new URLSearchParams(window.location.search);
    let token = urlParams.get('token');

    if (!token) {
        try {
            const response = await fetch('/get_or_create_token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    user_id: '', // Substituir conforme necessário
                    recipient_email: 'seu_email@dominio.com' // Substituir conforme necessário
                })
            });
            if (response.ok) {
                const data = await response.json();
                token = data.token;
            } else {
                console.error('Erro ao obter novo token', response.status);
                return; // Encerrar a execução se a requisição falhar
            }
        } catch (error) {
            console.error('Erro ao chamar a API para obter token', error);
            return; // Encerrar a execução em caso de erro
        }
    }

    let tokenInput = form.querySelector('input[name="token"]');
    if (!tokenInput) {
        tokenInput = document.createElement('input');
        tokenInput.setAttribute('type', 'hidden');
        tokenInput.setAttribute('name', 'token');
        form.appendChild(tokenInput);
    }
    tokenInput.value = token;

    // Logs para depuração
    console.log("Action Type:", actionType);
    console.log("Selected Entries:", selectedEntries);
    console.log("Token:", token);
    // Log para a URL de destino do form
    console.log("Form Action URL:", form.getAttribute('action'));

    const formData = new FormData(form);
    for (const [key, value] of formData.entries()) {
        console.log(`${key}: ${value}`);
    }
    // Submeter o formulário
    form.submit();
}




    document.getElementById('approve-selected').onclick = function() {
        submitForm('aprovar');
    };

    document.getElementById('reject-selected').onclick = function() {
        submitForm('reprovar');
    };



    function toggleSelectedActions() {
        var selected = document.querySelectorAll('input[name="selected_entries"]:checked').length > 0;
        var selectedActions = document.getElementById('selected-actions');
        var allActions = document.getElementById('all-actions');
        if (selected) {
            selectedActions.style.display = 'flex';
            allActions.style.display = 'none';
        } else {
            selectedActions.style.display = 'none';
            allActions.style.display = 'flex';
        }
    }

    function filterTable() {
        var input = document.getElementById('search');
        var filter = input.value.toLowerCase();
        var table = document.querySelector('table');
        var tr = table.getElementsByTagName('tr');
        for (var i = 1; i < tr.length; i++) {
            var td = tr[i].getElementsByTagName('td')[1];
            if (td) {
                var txtValue = td.textContent || td.innerText;
                if (txtValue.toLowerCase().indexOf(filter) > -1) {
                    tr[i].style.display = '';
                } else {
                    tr[i].style.display = 'none';
                }
            }
        }
    }

    document.getElementById('search').oninput = filterTable;
});
