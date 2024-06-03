from datetime import datetime, timedelta
import logging
from flask import Flask, request, jsonify, redirect
import requests
import os
from email_sender import send_email
from test_email import logger
from flask_cors import CORS
from waitress import serve

app = Flask(__name__)
#app.config['DEBUG'] = True
CORS(app)

#REDMINE_URL = os.getenv('REDMINE_URL')
#REDMINE_API_KEY = os.getenv('REDMINE_API_KEY')
REDMINE_URL = 'https://redmine5tec.evtit.com'
REDMINE_API_KEY = "ea8d896c01e60cbc31baf6e84e9d4bf8eee5033b"
API_URL = "https://192.168.1.76/"


@app.route('/')
def index():
    return "Hello world!"


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file and file.filename.endswith('.txt'):
        file_content = file.read().decode('utf-8')
        send_email(file_content)
        return jsonify({"message": "Email sent successfully"}), 200
    return jsonify({"error": "Invalid file type"}), 400


def get_time_entry(time_entry_id):
    url = f"{REDMINE_URL}/time_entries/{time_entry_id}.json"
    headers = {
        'X-Redmine-API-Key': REDMINE_API_KEY
    }
    response = requests.get(url, headers=headers, verify=False)
    return response.status_code, response.json()


def update_time_entry(time_entry_id, custom_fields):
    url = f"{REDMINE_URL}/time_entries/{time_entry_id}.json"
    headers = {
        'X-Redmine-API-Key': REDMINE_API_KEY,
        'Content-Type': 'application/json'
    }
    payload = {
        'time_entry': {
            'custom_fields': custom_fields
        }
    }
    response = requests.put(url, json=payload, headers=headers, verify=False)
    return response.status_code, response.text


def alterar_data_temporariamente(entry_id, nova_data):
    for _ in range(10):
        status_code, response = get_time_entry(entry_id)
        if status_code == 200:
            time_entry = response.get('time_entry', {})
            custom_fields = time_entry.get('custom_fields', [])
            time_entry['spent_on'] = nova_data
            payload = {'time_entry': {'spent_on': nova_data, 'custom_fields': custom_fields}}
            url = f"{REDMINE_URL}/time_entries/{entry_id}.json"
            headers = {
                'X-Redmine-API-Key': REDMINE_API_KEY,
                'Content-Type': 'application/json'
            }
            response = requests.put(url, json=payload, headers=headers, verify=False)
            if response.status_code in [200, 204]:
                return response.status_code, response.text
            else:
                error_message = response.json().get('errors', [])
                if any("já existente" in error for error in error_message):
                    nova_data = (datetime.strptime(nova_data, '%Y-%m-%d') + timedelta(days=1)).strftime('%Y-%m-%d')
                else:
                    return response.status_code, response.text
        else:
            return status_code, response
    return 400, {"errors": ["Não foi possível alterar a data após 10 tentativas"]}


def restaurar_data_original(entry_id, data_original):
    status_code, response = get_time_entry(entry_id)
    if status_code == 200:
        time_entry = response.get('time_entry', {})
        custom_fields = time_entry.get('custom_fields', [])
        time_entry['spent_on'] = data_original
        payload = {'time_entry': {'spent_on': data_original, 'custom_fields': custom_fields}}
        url = f"{REDMINE_URL}/time_entries/{entry_id}.json"
        headers = {
            'X-Redmine-API-Key': REDMINE_API_KEY,
            'Content-Type': 'application/json'
        }
        response = requests.put(url, json=payload, headers=headers, verify=False)
        return response.status_code, response.text
    else:
        return status_code, response


def aprovar_ou_reprovar(entry_id, tipo):
    status_code, response = get_time_entry(entry_id)
    if status_code == 200:
        time_entry = response.get('time_entry', {})
        custom_fields = time_entry.get('custom_fields', [])

        # Armazenar a data original
        data_original = time_entry.get('spent_on')

        # Definir uma nova data dentro do período permitido
        nova_data = (datetime.now() - timedelta(days=4)).strftime('%Y-%m-%d')
        data_atual = datetime.now().strftime('%Y-%m-%d')
        # Alterar a data temporariamente
        alterar_status, alterar_response = alterar_data_temporariamente(entry_id, nova_data)
        if alterar_status not in [200, 204]:
            return {"error": "Failed to temporarily change date", "details": alterar_response}

        for field in custom_fields:
            if field.get('name') == 'TS - Aprovado - EVT':
                field['value'] = '1' if tipo == 'aprovar' else '0'
            #if field.get('name') == 'TS - Aprovado - CLI':
            #   field['value'] = '1' if tipo == 'aprovar_selecionados' else '0'
            if field.get('name') == 'TS - Dt. Aprovação - EVT':
                field['value'] = data_atual if tipo == 'aprovar' else ''
            #if field.get('name') == 'TS - Dt. Aprovação - CLI':
            #field['value'] = data_atual if tipo == 'reprovar_selecionados' else ''

        update_status, update_response = update_time_entry(entry_id, custom_fields)

        if update_status == 200 or update_status == 204:
            # Restaurar a data original
            restaurar_data_original(entry_id, data_original)
            return {"message": f"Hora {'aprovada' if tipo == 'aprovar' else 'reprovada'} para ID: {entry_id}"}
        else:
            # Restaurar a data original em caso de falha
            restaurar_data_original(entry_id, data_original)
            return {"error": "Failed to update in Redmine", "details": update_response}
    else:
        return {"error": "Failed to fetch time entry from Redmine", "details": response}


@app.route('/aprovar_hora', methods=['GET'])
def aprovar_hora():
    data_id = request.args.get('id')
    return jsonify(aprovar_ou_reprovar(data_id, 'aprovar'))


@app.route('/reprovar_hora', methods=['GET'])
def reprovar_hora():
    data_id = request.args.get('id')
    return jsonify(aprovar_ou_reprovar(data_id, 'reprovar'))


@app.route('/validar_selecionados', methods=['POST'])
def validar_selecionados():
    selected_entries = request.form.getlist('selected_entries')
    tipo = request.form.get('tipo_req')

    if not selected_entries:
        return jsonify({"error": "No entries selected"}), 400

    if tipo not in ['aprovar', 'reprovar']:
        return jsonify({"error": "Invalid type"}), 400

    messages = []
    errors = []
    for entry_id in selected_entries:
        result = aprovar_ou_reprovar(entry_id, 'aprovar' if tipo == 'aprovar' else 'reprovar')
        if 'error' in result:
            errors.append(result)
        else:
            messages.append(result['message'])

    result = {"messages": messages}
    if errors:
        result["errors"] = errors
    return jsonify(result), 200 if not errors else 207


def send_email_task(file_content, recipient_emails, project_name, user_name):
    logger.info("Tarefa de envio de e-mail iniciada.")
    try:
        logger.info("Chamando função send_email com o seguinte conteúdo:")
        logger.info(file_content)
        for email in recipient_emails:
            send_email(file_content, email.strip(), project_name, user_name)
            logger.info(f"Enviando e-mail para: {email.strip()}")
        logger.info("E-mails enviados com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao enviar e-mails: {e}")


@app.route('/send_email_report', methods=['POST'])
def send_email_report():
    logger.info('Tentando obter o usuário logado.')
    response = requests.get(f'{REDMINE_URL}/users/current.json', headers={
        'X-Redmine-API-Key': REDMINE_API_KEY,
        'Content-Type': 'application/json'
    }, verify=False)

    if response.ok:
        user_data = response.json()
        user_id = user_data['user']['id']
        logger.info(f'Usuário logado obtido: {user_data["user"]["login"]}')

        today = datetime.today()
        seven_days_ago = today - timedelta(days=7)
        start_date = seven_days_ago.strftime('%Y-%m-%d')
        end_date = today.strftime('%Y-%m-%d')

        url = f'{REDMINE_URL}/time_entries.json?user_id={user_id}&from={start_date}&to={end_date}'
        entries_response = requests.get(url, headers={
            'X-Redmine-API-Key': REDMINE_API_KEY,
            'Content-Type': 'application/json'
        }, verify=False)

        if entries_response.ok:
            time_entries = entries_response.json().get('time_entries', [])
            table_html = create_html_table(time_entries)
            recipient_emails = request.headers.get('recipient', '').split(',')  # Obtém a lista de e-mails dos headers da requisição
            if not recipient_emails or recipient_emails == ['']:
                logger.error('Nenhum e-mail de destinatário fornecido.')
                return jsonify({'error': 'Nenhum e-mail de destinatário fornecido.'}), 400
            project_name = time_entries[0]['project']['name']
            user_name = time_entries[0]['user']['name']
            send_email_task(table_html, recipient_emails, project_name, user_name)
            return jsonify({'message': 'Relatório enviado com sucesso.'}), 200
        else:
            logger.error('Erro ao buscar entradas de tempo.')
            return jsonify({'error': 'Erro ao buscar entradas de tempo'}), 500
    else:
        logger.error('Erro ao obter o usuário logado. Redirecionando para login.')
        return redirect(f'{REDMINE_URL}/login')


@app.route('/send_unitary_report', methods=['POST'])
def send_unitary_report():
    entry_id = request.headers.get('id', '')
    if not entry_id:
        return jsonify({'error': 'ID de entrada não fornecido.'}), 400

    recipient_emails = request.headers.get('recipient', '').split(',')
    if not recipient_emails or recipient_emails == ['']:
        logger.error('Nenhum e-mail de destinatário fornecido.')
        return jsonify({'error': 'Nenhum e-mail de destinatário fornecido.'}), 400

    try:
        status_code, response = get_time_entry(entry_id)
        if status_code == 200:
            time_entry = response.get('time_entry', {})
            project_name = time_entry['project']['name']
            user_name = time_entry['user']['name']
            table_html = create_html_unitary_table(time_entry)
            send_email_task(table_html, recipient_emails, project_name, user_name)

        return jsonify({'message': 'Relatório enviado com sucesso.'}), 200

    except Exception as e:
        logger.error(f"Erro ao processar a solicitação: {e}")
        return jsonify({'error': 'Erro ao processar a solicitação.'}), 500

@app.route('/aprovar_todos', methods=['GET'])
def aprovar_todos():
    return atualizar_todas_entradas(aprovacao=True)

@app.route('/reprovar_todos', methods=['GET'])
def reprovar_todos():
    return atualizar_todas_entradas(aprovacao=False)

def atualizar_todas_entradas(aprovacao):
    today = datetime.today()
    seven_days_ago = today - timedelta(days=7)
    start_date = seven_days_ago.strftime('%Y-%m-%d')
    end_date = today.strftime('%Y-%m-%d')

    url = f'{REDMINE_URL}/time_entries.json?from={start_date}&to={end_date}'
    response = requests.get(url, headers={
        'X-Redmine-API-Key': REDMINE_API_KEY,
        'Content-Type': 'application/json'
    }, verify=False)

    if response.ok:
        time_entries = response.json().get('time_entries', [])
        errors = []
        for entry in time_entries:
            entry_id = entry['id']
            status_code, response = get_time_entry(entry_id)
            if status_code == 200:
                time_entry = response.get('time_entry', {})
                custom_fields = time_entry.get('custom_fields', [])

                # Armazenar a data original
                data_original = time_entry.get('spent_on')

                # Definir uma nova data dentro do período permitido
                nova_data = (datetime.now() - timedelta(days=4)).strftime('%Y-%m-%d')
                data_atual = datetime.now().strftime('%Y-%m-%d')

                # Alterar a data temporariamente
                alterar_status, alterar_response = alterar_data_temporariamente(entry_id, nova_data)
                if alterar_status not in [200, 204]:
                    errors.append({
                        'id': entry_id,
                        'status': alterar_status,
                        'response': alterar_response
                    })
                    continue

                for field in custom_fields:
                    if field.get('name') == 'TS - Aprovado - EVT':
                        field['value'] = '1' if aprovacao else '0'
                    if field.get('name') == 'TS - Dt. Aprovação - EVT':
                        field['value'] = end_date if aprovacao else ''

                update_status, update_response = update_time_entry(entry_id, custom_fields)
                if update_status == 200 or update_status == 204:
                    # Restaurar a data original
                    restaurar_data_original(entry_id, data_original)
                else:
                    # Restaurar a data original em caso de falha
                    restaurar_data_original(entry_id, data_original)
                    errors.append({
                        'id': entry_id,
                        'status': update_status,
                        'response': update_response
                    })

        if errors:
            return jsonify({
                "error": "Some entries failed to update",
                "details": errors
            }), 207
        if aprovacao:
            return jsonify({"message": "Todas as horas foram aprovadas!"}), 200
        else:
            return jsonify({"message": "Todas as horas foram reprovadas!"}), 200
    else:
        return jsonify({"error": "Failed to fetch time entries from Redmine", "details": response.json()}), 400


def create_html_unitary_table(entry):
    table = '''
    <form id="time_entries_form" method="post" action="https://192.168.1.76/validar_selecionados">
    <input type="hidden" name="tipo" value="">
    <table style="border: 1px solid black; border-collapse: collapse;">
    <thead>
      <tr>
        <th style="border: 1px solid black;">ID</th>
        <th style="border: 1px solid black;">Projeto</th>
        <th style="border: 1px solid black;">Colaborador</th>
        <th style="border: 1px solid black;">Horas</th>
        <th style="border: 1px solid black;">Comentários</th>
        <th style="border: 1px solid black;">Lançada em</th>
        <th style="border: 1px solid black;">Hora inicial (HH:MM)</th>
        <th style="border: 1px solid black;">Hora final (HH:MM)</th>
        <th style="border: 1px solid black;">Ações</th>

      </tr>
    </thead>
    <tbody>
    '''

    hora_inicial = next(
        (field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora inicial (HH:MM)'), '')
    hora_final = next((field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora final (HH:MM)'),
                      '')
    identificacao_cliente = next(
        (field['value'] for field in entry['custom_fields'] if field['name'] == 'Identificação do Cliente'), '')
    local_trabalho = next(
        (field['value'] for field in entry['custom_fields'] if field['name'] == 'Local de trabalho'), '')
    responsavel_cliente = next(
        (field['value'] for field in entry['custom_fields'] if field['name'] == 'Responsável Cliente'), '')
    ts_aprovado_evt = next(
        (field['value'] for field in entry['custom_fields'] if field['name'] == 'TS - Aprovado - EVT'), '')
    ts_aprovado_cli = next(
        (field['value'] for field in entry['custom_fields'] if field['name'] == 'TS - Aprovado - CLI'), '')
    ts_dt_aprovacao_evt = next(
        (field['value'] for field in entry['custom_fields'] if field['name'] == 'TS - Dt. Aprovação - EVT'), '')

    table += f'''
        <tr>
          <td style="border: 1px solid black;">{entry['id']}</td>
          <td style="border: 1px solid black;">{entry['project']['name']}</td>
          <td style="border: 1px solid black;">{entry['user']['name']}</td>
          <td style="border: 1px solid black;">{entry['hours']}</td>
          <td style="border: 1px solid black;">{entry['comments']}</td>
          <td style="border: 1px solid black;">{entry['spent_on']}</td>
          <td style="border: 1px solid black;">{hora_inicial}</td>
          <td style="border: 1px solid black;">{hora_final}</td>
          <td style="border: 1px solid black;">
            <a href="{API_URL}aprovar_hora?id={entry['id']}" style="background-color: green; color: white; padding: 5px 10px; text-decoration: none; border-radius: 5px; font-weight: bold;">Aprovar</a>
            <a href="{API_URL}reprovar_hora?id={entry['id']}" style="background-color: red; color: white; padding: 5px 10px; text-decoration: none; border-radius: 5px; font-weight: bold;">Reprovar</a>
          </td>
        </tr>
        '''

    table += '''
    </tbody>
    </table>
    </form>
    '''

    return table


def create_html_table(time_entries):
    table = '''
    <form id="time_entries_form" method="post" action="https://192.168.1.76/validar_selecionados">
    <input type="hidden" name="tipo" value="">
    <table style="border: 1px solid black; border-collapse: collapse;">
    <thead>
      <tr>
        <th style="border: 1px solid black;"></th>
        <th style="border: 1px solid black;">ID</th>
        <th style="border: 1px solid black;">Projeto</th>
        <th style="border: 1px solid black;">Colaborador</th>
        <th style="border: 1px solid black;">Horas</th>
        <th style="border: 1px solid black;">Comentários</th>
        <th style="border: 1px solid black;">Lançada em</th>
        <th style="border: 1px solid black;">Hora inicial (HH:MM)</th>
        <th style="border: 1px solid black;">Hora final (HH:MM)</th>
        <th style="border: 1px solid black;">Ações</th>
        
      </tr>
    </thead>
    <tbody>
    '''

    for entry in time_entries:
        hora_inicial = next(
            (field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora inicial (HH:MM)'), '')
        hora_final = next((field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora final (HH:MM)'),
                          '')
        identificacao_cliente = next(
            (field['value'] for field in entry['custom_fields'] if field['name'] == 'Identificação do Cliente'), '')
        local_trabalho = next(
            (field['value'] for field in entry['custom_fields'] if field['name'] == 'Local de trabalho'), '')
        responsavel_cliente = next(
            (field['value'] for field in entry['custom_fields'] if field['name'] == 'Responsável Cliente'), '')
        ts_aprovado_evt = next(
            (field['value'] for field in entry['custom_fields'] if field['name'] == 'TS - Aprovado - EVT'), '')
        ts_aprovado_cli = next(
            (field['value'] for field in entry['custom_fields'] if field['name'] == 'TS - Aprovado - CLI'), '')
        ts_dt_aprovacao_evt = next(
            (field['value'] for field in entry['custom_fields'] if field['name'] == 'TS - Dt. Aprovação - EVT'), '')

        table += f'''
        <tr>
          <td style="border: 1px solid black;"><input type="checkbox" class="select_entry" name="selected_entries" value="{entry['id']}"></td>
          <td style="border: 1px solid black;">{entry['id']}</td>
          <td style="border: 1px solid black;">{entry['project']['name']}</td>
          <td style="border: 1px solid black;">{entry['user']['name']}</td>
          <td style="border: 1px solid black;">{entry['hours']}</td>
          <td style="border: 1px solid black;">{entry['comments']}</td>
          <td style="border: 1px solid black;">{entry['spent_on']}</td>
          <td style="border: 1px solid black;">{hora_inicial}</td>
          <td style="border: 1px solid black;">{hora_final}</td>
          <td style="border: 1px solid black;">
            <a href="{API_URL}aprovar_hora?id={entry['id']}" style="background-color: green; color: white; padding: 5px 10px; text-decoration: none; border-radius: 5px; font-weight: bold;">Aprovar</a>
            <a href="{API_URL}reprovar_hora?id={entry['id']}" style="background-color: red; color: white; padding: 5px 10px; text-decoration: none; border-radius: 5px; font-weight: bold;">Reprovar</a>
          </td>
        </tr>
        '''

    table += '''
    </tbody>
    </table>
    <p>Por favor, escolha uma das opções abaixo:</p>
    <a href="https://192.168.1.76/aprovar_todos" 
       style="background-color: green; color: white; padding: 5px 10px; text-decoration: none; border-radius: 5px; font-weight: bold;">
       Aprovar Todos
    </a>
    <a href="https://192.168.1.76/reprovar_todos" 
       style="background-color: red; color: white; padding: 5px 10px; text-decoration: none; border-radius: 5px; font-weight: bold;">
       Reprovar Todos
    </a>
    <button type="submit" name="tipo_req" value="aprovar" style="background-color: green; color: white; padding: 5px 10px; text-decoration: none; border-radius: 5px; font-weight: bold;">
       Aprovar Selecionados
    </button>
    <button type="submit" name="tipo_req" value="reprovar" style="background-color: red; color: white; padding: 5px 10px; text-decoration: none; border-radius: 5px; font-weight: bold;">
       Reprovar Selecionados
    </button>
    </form>
    '''

    return table


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    #app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000)
    serve(app, host='127.0.0.1', port=5000)
