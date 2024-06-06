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

    function submitForm(actionType) {
    const form = document.getElementById('time_entries_form');
    form.setAttribute('target', '_blank');
    const tipoInput = form.querySelector('input[name="tipo"]');
    if (tipoInput) {
        tipoInput.value = actionType;
    } else {
        const newInput = document.createElement('input');
        newInput.setAttribute('type', 'hidden');
        newInput.setAttribute('name', 'tipo');
        newInput.setAttribute('value', actionType);
        form.appendChild(newInput);
    }

    var selectedEntries = [];
    var checkboxes = document.querySelectorAll('input[name="selected_entries"]:checked');
    for (var checkbox of checkboxes) {
        selectedEntries.push(checkbox.value);
    }

    const selectedEntriesInput = form.querySelector('input[name="selected_entries"]');
    if (selectedEntriesInput) {
        selectedEntriesInput.value = selectedEntries.join(',');
    } else {
        const newSelectedEntriesInput = document.createElement('input');
        newSelectedEntriesInput.setAttribute('type', 'hidden');
        newSelectedEntriesInput.setAttribute('name', 'selected_entries');
        newSelectedEntriesInput.setAttribute('value', selectedEntries.join(','));
        form.appendChild(newSelectedEntriesInput);
    }

    // Adicionar o token à URL
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    if (token) {
        const action = form.getAttribute('action');
        form.setAttribute('action', `${action}?token=${token}`);
    }

    form.submit();
}


    document.getElementById('approve-selected').onclick = function() {
        submitForm('aprovar');
    };

    document.getElementById('reject-selected').onclick = function() {
        submitForm('reprovar');
    };

    document.getElementById('time_entries_form').onsubmit = function(e) {
        e.preventDefault();
        var form = e.target;
        var formData = new FormData(form);
        var params = new URLSearchParams();

        for (var pair of formData.entries()) {
            params.append(pair[0], pair[1]);
        }

        var url = form.action + '?' + params.toString();
        window.open(url, '_blank');
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
