from datetime import datetime, timedelta
import logging
from flask import Flask, request, jsonify, redirect, render_template, url_for, session, render_template_string
import requests
import os
import uuid
from email_sender import send_email
from test_email import logger
from flask_cors import CORS
from waitress import serve
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
CORS(app)

REDMINE_URL = 'https://redmine5tec.evtit.com'
REDMINE_API_KEY = "ea8d896c01e60cbc31baf6e84e9d4bf8eee5033b"
API_URL = "http://192.168.1.119:5000/"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class AccessToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    recipient_email = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ApprovalRejectionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    entry_id = db.Column(db.Integer, nullable=False)
    entry_date = db.Column(db.String(50), nullable=False)
    hours = db.Column(db.Float, nullable=False)
    log_date = db.Column(db.String(50), default=datetime.utcnow, nullable=False)

def create_database():
    with app.app_context():
        db.drop_all()
        db.create_all()

create_database()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.args.get('token')
        if token:
            access_token = AccessToken.query.filter_by(token=token).first()
            if access_token:
                return f(*args, **kwargs)
        return redirect(url_for('login'))

    return decorated_function

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            return "User already exists", 400
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/upload', methods=['POST'])
@login_required
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

@app.route('/aprovar_hora', methods=['GET'])
def aprovar_hora():
    data_id = request.args.get('id')
    token = request.args.get('token')
    result = aprovar_ou_reprovar(data_id, 'aprovar', get_current_user(), token)
    if 'error' in result:
        return jsonify(result), 400
    else:
        return jsonify(result), 200

@app.route('/reprovar_hora', methods=['GET'])
def reprovar_hora():
    data_id = request.args.get('id')
    token = request.args.get('token')
    result = aprovar_ou_reprovar(data_id, 'reprovar', get_current_user(), token)
    if 'error' in result:
        return jsonify(result), 400
    else:
        return jsonify(result), 200

@app.route('/validar_selecionados', methods=['POST', 'GET'])
@login_required
def validar_selecionados():
    if request.method == 'POST':
        selected_entries = request.form.getlist('selected_entries')
    else:
        selected_entries = request.args.get('selected_entries').split(',')

    tipo = request.form.get('tipo_req') if request.method == 'POST' else request.args.get('tipo')

    if not selected_entries:
        return jsonify({"error": "No entries selected"}), 400
    if tipo not in ['aprovar', 'reprovar']:
        return jsonify({"error": "Invalid type"}), 400

    messages = []
    errors = []

    for entry_id in selected_entries:
        token = request.args.get('token')
        result = aprovar_ou_reprovar(entry_id, 'aprovar' if tipo == 'aprovar' else 'reprovar', get_current_user(), token)
        if 'error' in result:
            errors.append(result)
        else:
            messages.append(result['message'])

    result = {"messages": messages}
    if errors:
        result["errors"] = errors

    return jsonify(result), 200 if not errors else 207

def send_email_task(file_content, recipient_emails, project_name, user_id, user_name):
    logger.info("Tarefa de envio de e-mail iniciada.")
    try:
        logger.info("Chamando função send_email com o seguinte conteúdo:")
        logger.info(file_content)
        for email in recipient_emails:
            token = get_or_create_token(user_id, email)
            link = f"{API_URL}relatorio_horas/{user_id}?token={token}"
            email_content = f"{file_content}\n\nPara visualizar as entradas de tempo, acesse o link: <a href='{link}'>relatório</a>"
            send_email(email_content, email.strip(), project_name, user_name)
            logger.info(f"Enviando e-mail para: {email.strip()}")
        logger.info("E-mails enviados com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao enviar e-mails: {e}")

def get_current_user():
    logger.info('Tentando obter o usuário logado.')
    response = requests.get(f'{REDMINE_URL}/users/current.json', headers={
        'X-Redmine-API-Key': REDMINE_API_KEY,
        'Content-Type': 'application/json'
    }, verify=False)
    if response.ok:
        user_data = response.json()
        logger.info(f'Usuário logado obtido: {user_data["user"]["login"]}')
        return user_data
    else:
        logger.error('Erro ao obter o usuário logado. Redirecionando para login.')
        return redirect(f'{REDMINE_URL}/login')

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
        user_email = user_data['user']
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
            unapproved_entries = [entry for entry in time_entries if any(
                field['name'] == 'TS - Aprovado - EVT' and field['value'] == '0' for field in
                entry.get('custom_fields', []))]

            if not unapproved_entries:
                logger.warning('Nenhuma entrada de tempo não aprovada encontrada.')
                return jsonify({'error': 'Nenhuma entrada de tempo não aprovada encontrada.'}), 400

            table_html = create_html_table_mail(unapproved_entries)
            recipient_emails = request.headers.get('recipient', '').split(',')
            if not recipient_emails or recipient_emails == ['']:
                logger.error('Nenhum e-mail de destinatário fornecido.')
                return jsonify({'error': 'Nenhum e-mail de destinatário fornecido.'}), 400
            project_name = unapproved_entries[0]['project']['name']
            user_name = unapproved_entries[0]['user']['name']
            send_email_task(table_html, recipient_emails, project_name, user_id, user_name)
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
            for email in recipient_emails:
                token = get_or_create_token(time_entry['user']['id'], email)
                link = f"{API_URL}relatorio_horas/{time_entry['user']['id']}?token={token}"
                email_content = f"{table_html}\n\nPara visualizar as entradas de tempo, acesse o link: <a href='{link}'>relatório</a>"
                send_email(email_content, email.strip(), project_name, user_name)

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
    user = get_current_user()
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
                    if field.get('name') == 'TS - Aprovador - EVT':
                        field['value'] = user['user']['mail'] if aprovacao else ''

                update_status, update_response = update_time_entry(entry_id, custom_fields)
                if update_status == 200 or 204:
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
    <form id="time_entries_form" method="get" action="http://192.168.1.119:5000/validar_selecionados">
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
            <a href="{API_URL}aprovar_hora?id={entry['id']}&token={request.args.get('token')}" style="background-color: green; color: white; padding: 5px 10px; text-decoration: none; border-radius: 5px; font-weight: bold;" target="_blank">Aprovar</a>
            <a href="{API_URL}reprovar_hora?id={entry['id']}&token={request.args.get('token')}" style="background-color: red; color: white; padding: 5px 10px; text-decoration: none; border-radius: 5px; font-weight: bold;" target="_blank">Reprovar</a>
          </td>
        </tr>
        '''

    table += '''
    </tbody>
    </table>
    </form>
    '''

    return table

def create_html_table_mail(time_entries):
    table = '''
    <form id="time_entries_form" method="post" action="">
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
          <td style="border: 1px solid black;">{entry['id']}</td>
          <td style="border: 1px solid black;">{entry['project']['name']}</td>
          <td style="border: 1px solid black;">{entry['user']['name']}</td>
          <td style="border: 1px solid black;">{entry['hours']}</td>
          <td style="border: 1px solid black;">{entry['comments']}</td>
          <td style="border: 1px solid black;">{entry['spent_on']}</td>
          <td style="border: 1px solid black;">{hora_inicial}</td>
          <td style="border: 1px solid black;">{hora_final}</td>
        </tr>
        '''

    table += '''
    </tbody>
    </table>
    </form>
    '''

    return table

@app.route('/relatorio_horas', methods=['GET'])
def relatorio_horas_geral():
    try:
        # Define o período de 30 dias
        today = datetime.today() + timedelta(days=1)
        thirty_days_ago = today - timedelta(days=30)
        start_date = thirty_days_ago.strftime('%Y-%m-%d')
        end_date = today.strftime('%Y-%m-%d')

        # Faz uma requisição para obter as entradas de tempo do Redmine
        url = f'{REDMINE_URL}/time_entries.json?from={start_date}&to={end_date}'
        entries_response = requests.get(url, headers={
            'X-Redmine-API-Key': REDMINE_API_KEY,
            'Content-Type': 'application/json'
        }, verify=False)

        if entries_response.ok:
            # Filtra as entradas de tempo para incluir apenas aquelas que não foram aprovadas
            time_entries = entries_response.json().get('time_entries', [])
            unapproved_entries = [entry for entry in time_entries if any(
                field['name'] == 'TS - Aprovado - EVT' and field['value'] == '0' for field in
                entry.get('custom_fields', []))]

            if not unapproved_entries:
                logger.warning(
                    f"Nenhuma entrada de tempo não aprovada encontrada no período de {start_date} a {end_date}")

            table_html = create_html_table(unapproved_entries)

            # Template HTML para renderizar a página
            html_template = f'''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Tempo gasto</title>
                <link rel="stylesheet" type="text/css" href="{{{{ url_for('static', filename='style.css') }}}}">
                <script>
                    function filterTable() {{
                        var input, filter, table, tr, td, i, j, txtValue;
                        input = document.getElementById("filterInput");
                        filter = input.value.toUpperCase();
                        table = document.getElementById("time_entries_table");
                        tr = table.getElementsByTagName("tr");

                        for (i = 1; i < tr.length; i++) {{
                            tr[i].style.display = "none";
                            td = tr[i].getElementsByTagName("td");
                            for (j = 0; j < td.length; j++) {{
                                if (td[j]) {{
                                    txtValue = td[j].textContent || td[j].innerText;
                                    if (txtValue.toUpperCase().indexOf(filter) > -1) {{
                                        tr[i].style.display = "";
                                        break;
                                    }}
                                }}
                            }}
                        }}
                    }}

                    function toggleAll(source) {{
                        checkboxes = document.getElementsByName('selected_entries');
                        for(var i=0, n=checkboxes.length;i<n;i++) {{
                            checkboxes[i].checked = source.checked;
                        }}
                    }}
                </script>
            </head>
            <body>
                <div id="header">
                    <div class="header-logo">
                        <img src="{{{{ url_for('static', filename='transparent_evt_logo.png') }}}}" alt="EVT">
                        <h1>EVT - Lançamento de Horas</h1>
                    </div>
                </div>
                <div class="container">
                    <form id="time_entries_form" method="get" action="http://192.168.1.119:5000/validar_selecionados">
                        <div class="filters">
                            <label for="filterInput">Buscar:</label>
                            <input type="text" id="filterInput" onkeyup="filterTable()" placeholder="Digite para buscar...">
                        </div>
                        {table_html}
                        <div id="all-actions" class="btn-group">
                            <a href="{API_URL}aprovar_todos" class="btn btn-approve" target="_blank">Aprovar Todos</a>
                            <a href="{API_URL}reprovar_todos" class="btn btn-reject" target="_blank">Reprovar Todos</a>
                        </div>
                        <div id="selected-actions" class="btn-group">
                            <button type="button" id="approve-selected" class="btn btn-approve" data-action="aprovar">Aprovar Selecionados</button>
                            <button type="button" id="reject-selected" class="btn btn-reject" data-action="reprovar">Reprovar Selecionados</button>
                        </div>
                    </form>
                </div>
            </body>
            </html>
            '''

            return render_template_string(html_template)
        else:
            logger.error(f"Erro ao buscar entradas de tempo: {entries_response.status_code}")
            return jsonify({"error": "Erro ao buscar entradas de tempo"}), 500
    except Exception as e:
        logger.error(f"Erro ao gerar a página HTML: {e}")
        return jsonify({"error": "Erro ao gerar a página HTML"}), 500

@app.route('/relatorio_horas/<int:user_id>', methods=['GET'])
#@token_required
def relatorio_horas(user_id):
    try:
        # Faz uma requisição para obter o usuário pelo ID fornecido na URL
        user_url = f'{REDMINE_URL}/users/{user_id}.json'
        user_response = requests.get(user_url, headers={
            'X-Redmine-API-Key': REDMINE_API_KEY,
            'Content-Type': 'application/json'
        }, verify=False)

        if not user_response.ok:
            logger.error(f"Erro ao buscar usuário com ID {user_id}: {user_response.status_code}")
            return jsonify({"error": "Usuário não encontrado"}), 404

        user = user_response.json()
        user_name = user['user']['firstname'] + ' ' + user['user']['lastname']

        # Obter parâmetros de filtro
        project_id = request.args.get('project_id')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        # Definir datas padrão (últimos 30 dias) se não fornecidas
        if not start_date or not end_date:
            today = datetime.today()
            thirty_days_ago = today - timedelta(days=30)
            start_date = thirty_days_ago.strftime('%Y-%m-%d')
            end_date = today.strftime('%Y-%m-%d')

        # Construir URL de requisição com filtros
        url = f'{REDMINE_URL}/time_entries.json?user_id={user_id}&from={start_date}&to={end_date}'
        if project_id:
            url += f'&project_id={project_id}'

        entries_response = requests.get(url, headers={
            'X-Redmine-API-Key': REDMINE_API_KEY,
            'Content-Type': 'application/json'
        }, verify=False)

        if entries_response.ok:
            # Filtra as entradas de tempo para incluir apenas aquelas que não foram aprovadas
            time_entries = entries_response.json().get('time_entries', [])
            unapproved_entries = [entry for entry in time_entries if any(
                field['name'] == 'TS - Aprovado - EVT' and field['value'] == '0' for field in
                entry.get('custom_fields', []))]

            if not unapproved_entries:
                logger.warning(
                    f"Nenhuma entrada de tempo não aprovada encontrada para o usuário ID {user_id} no período de {start_date} a {end_date}")

            table_html = create_html_table(unapproved_entries)

            # Template HTML para renderizar a página com filtros
            html_template = f'''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Tempo gasto</title>
                <link rel="stylesheet" type="text/css" href="{{{{ url_for('static', filename='style.css') }}}}">
                <script>
                    function filterTable() {{
                        var input, filter, table, tr, td, i, j, txtValue;
                        input = document.getElementById("filterInput");
                        filter = input.value.toUpperCase();
                        table = document.getElementById("time_entries_table");
                        tr = table.getElementsByTagName("tr");

                        for (i = 1; i < tr.length; i++) {{
                            tr[i].style.display = "none";
                            td = tr[i].getElementsByTagName("td");
                            for (j = 0; j < td.length; j++) {{
                                if (td[j]) {{
                                    txtValue = td[j].textContent || td[j].innerText;
                                    if (txtValue.toUpperCase().indexOf(filter) > -1) {{
                                        tr[i].style.display = "";
                                        break;
                                    }}
                                }}
                            }}
                        }}
                    }}

                    function toggleAll(source) {{
                        checkboxes = document.getElementsByName('selected_entries');
                        for(var i=0, n=checkboxes.length;i<n;i++) {{
                            checkboxes[i].checked = source.checked;
                        }}
                    }}
                </script>
            </head>
            <body>
                <div id="header">
                    <div class="header-logo">
                        <img src="{{{{ url_for('static', filename='transparent_evt_logo.png') }}}}" alt="EVT">
                        <h1>EVT - Lançamento de Horas - {user_name}</h1>
                    </div>
                </div>
                <div class="container">
                    <form id="time_entries_form" method="get" action="http://192.168.1.119:5000/validar_selecionados">
                        <div class="filters">
                            <label for="filterInput">Buscar:</label>
                            <input type="text" id="filterInput" onkeyup="filterTable()" placeholder="Digite para buscar...">
                        </div>
                        {table_html}
                        <div id="all-actions" class="btn-group">
                            <a href="{API_URL}aprovar_todos?user_id={user_id}" class="btn btn-approve" target="_blank">Aprovar Todos</a>
                            <a href="{API_URL}reprovar_todos?user_id={user_id}" class="btn btn-reject" target="_blank">Reprovar Todos</a>
                        </div>
                        <div id="selected-actions" class="btn-group">
                            <button type="button" id="approve-selected" class="btn btn-approve" data-action="aprovar">Aprovar Selecionados</button>
                            <button type="button" id="reject-selected" class="btn btn-reject" data-action="reprovar">Reprovar Selecionados</button>
                        </div>
                    </form>
                </div>
                <script src="{{{{ url_for('static', filename='script.js') }}}}"></script>
            </body>
            </html>
            '''

            return render_template_string(html_template)
        else:
            logger.error(f"Erro ao buscar entradas de tempo: {entries_response.status_code}")
            return jsonify({"error": "Erro ao buscar entradas de tempo"}), 500
    except Exception as e:
        logger.error(f"Erro ao gerar a página HTML: {e}")
        return jsonify({"error": "Erro ao gerar a página HTML"}), 500

def create_html_table(time_entries):
    table = '''
    <table id="time_entries_table">
    <thead>
      <tr>
        <th><input type="checkbox" id="select_all" onclick="toggleAll(this)"></th>
        <th>Data</th>
        <th>Usuário</th>
        <th>Atividade</th>
        <th>Projeto</th>
        <th>Comentário</th>
        <th>Hora inicial (HH:MM)</th>
        <th>Hora final (HH:MM)</th>
        <th>Horas</th>
        <th>Ações</th>
      </tr>
    </thead>
    <tbody>
    '''

    for entry in time_entries:
        hora_inicial = next(
            (field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora inicial (HH:MM)'), '')
        hora_final = next((field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora final (HH:MM)'),
                          '')
        project_name = entry['project']['name'] if 'project' in entry else 'N/A'

        table += f'''
        <tr>
          <td><input type="checkbox" name="selected_entries" value="{entry['id']}"></td>
          <td>{entry['spent_on']}</td>
          <td>{entry['user']['name']}</td>
          <td>{entry['activity']['name']}</td>
          <td>{project_name}</td>
          <td>{entry['comments']}</td>
          <td>{hora_inicial}</td>
          <td>{hora_final}</td>
          <td>{entry['hours']}</td>
          <td>
            <a href="{API_URL}aprovar_hora?id={entry['id']}&token={request.args.get('token')}" class="btn btn-approve-table" target="_blank">Aprovar</a>
            <a href="{API_URL}reprovar_hora?id={entry['id']}&token={request.args.get('token')}" class="btn btn-reject-table" target="_blank">Reprovar</a>
          </td>
        </tr>
        '''

    table += '''
    </tbody>
    </table>
    <br>
    '''

    return table

def get_time_entry(time_entry_id):
    url = f"{REDMINE_URL}/time_entries/{time_entry_id}.json"
    headers = {'X-Redmine-API-Key': REDMINE_API_KEY}
    response = requests.get(url, headers=headers, verify=False)
    return response.status_code, response.json()

def update_time_entry(time_entry_id, custom_fields):
    url = f"{REDMINE_URL}/time_entries/{time_entry_id}.json"
    headers = {
        'X-Redmine-API-Key': REDMINE_API_KEY,
        'Content-Type': 'application/json'
    }
    payload = {'time_entry': {'custom_fields': custom_fields}}
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

def aprovar_ou_reprovar(entry_id, tipo, user, token):
    status_code, response = get_time_entry(entry_id)
    if status_code == 200:
        time_entry = response.get('time_entry', {})
        custom_fields = time_entry.get('custom_fields', [])
        data_original = time_entry.get('spent_on')
        nova_data = (datetime.now() - timedelta(days=4)).strftime('%Y-%m-%d')
        data_atual = datetime.now().strftime('%Y-%m-%d')
        alterar_status, alterar_response = alterar_data_temporariamente(entry_id, nova_data)
        if alterar_status not in [200, 204]:
            return {"error": "Failed to temporarily change date", "details": alterar_response}
        for field in custom_fields:
            if field.get('name') == 'TS - Aprovado - EVT':
                field['value'] = '1' if tipo == 'aprovar' else '0'
            if field.get('name') == 'TS - Dt. Aprovação - EVT':
                field['value'] = data_atual if tipo == 'aprovar' else ''
            if field.get('name') == 'TS - Aprovador - EVT':
                field['value'] = user['user']['mail'] if tipo == 'aprovar' else ''
        update_status, update_response = update_time_entry(entry_id, custom_fields)
        if update_status == 200 or 204:
            restaurar_data_original(entry_id, data_original)
            log_approval_rejection(entry_id, time_entry['spent_on'], time_entry['hours'], tipo, token)
            return {"message": f"Hora {'aprovada' if tipo == 'aprovar' else 'reprovada'} para ID: {entry_id}"}
        else:
            restaurar_data_original(entry_id, data_original)
            return {"error": "Failed to update in Redmine", "details": update_response}
    else:
        return {"error": "Failed to fetch time entry from Redmine", "details": response}

@app.route('/api/horas_nao_aprovadas', methods=['GET'])
@login_required
def horas_nao_aprovadas():
    try:
        url = f'{REDMINE_URL}/time_entries.json?limit=1000'
        response = requests.get(url, headers={
            'X-Redmine-API-Key': REDMINE_API_KEY,
            'Content-Type': 'application/json'
        }, verify=False)

        if response.ok:
            time_entries = response.json().get('time_entries', [])
            result = []
            for entry in time_entries:
                ts_aprovado_evt = next(
                    (field['value'] for field in entry['custom_fields'] if field['name'] == 'TS - Aprovado - EVT'), '')
                if ts_aprovado_evt == '0':
                    result.append(entry)
            return jsonify(result), 200
        else:
            return jsonify({"error": "Erro ao buscar entradas de tempo"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/recipients_tokens', methods=['GET'])
#@login_required
def get_recipients_tokens():
    try:
        # Consultar todos os tokens de acesso no banco de dados
        access_tokens = AccessToken.query.all()

        # Criar uma lista de dicionários com os dados dos tokens
        tokens_list = [
            {
                "recipient_email": token.recipient_email,
                "token": token.token
            }
            for token in access_tokens
        ]

        # Retornar os dados em formato JSON
        return jsonify(tokens_list), 200
    except Exception as e:
        logger.error(f"Erro ao buscar tokens: {e}")
        return jsonify({"error": "Erro ao buscar tokens"}), 500

@app.route('/clean_tokens', methods=['POST'])
def clean_tokens():
    try:
        num_rows_deleted = db.session.query(AccessToken).delete()
        db.session.commit()
        return jsonify({"message": f"{num_rows_deleted} tokens deletados."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

def get_or_create_token(user_id, recipient_email):
    # Tenta encontrar um token existente para o destinatário
    existing_token = AccessToken.query.filter_by(recipient_email=recipient_email).first()

    if existing_token:
        return existing_token.token

    # Se não houver token existente, cria um novo
    token = str(uuid.uuid4())
    access_token = AccessToken(token=token, user_id=user_id, recipient_email=recipient_email)
    db.session.add(access_token)
    db.session.commit()
    return token


def log_approval_rejection(entry_id, entry_date, hours, action, token):
    try:
        log_entry = ApprovalRejectionLog(
            token=token,
            action=action,
            entry_id=entry_id,
            entry_date=entry_date,
            hours=hours
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        logger.error(f"Erro ao salvar log de {action} para entrada ID {entry_id}: {e}")

@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        logs = ApprovalRejectionLog.query.all()
        logs_list = [
            {
                "id": log.id,
                "token": log.token,
                "action": log.action,
                "entry_id": log.entry_id,
                "entry_date": log.entry_date,
                "hours": log.hours,
                "log_date": log.log_date
            }
            for log in logs
        ]
        return jsonify(logs_list), 200
    except Exception as e:
        logger.error(f"Erro ao buscar logs: {e}")
        return jsonify({"error": "Erro ao buscar logs"}), 500

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    serve(app, host='127.0.0.1', port=port)
