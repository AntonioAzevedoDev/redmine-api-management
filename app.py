from collections import defaultdict
from datetime import datetime, timedelta
from flask import render_template_string
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

REDMINE_URL = 'https://redmineqas.evtit.com'
REDMINE_API_KEY = "14f242e3ec7d71044d2b15dc285fd0b2603b9f0a"
API_URL = "https://timesheetqas.evtit.com/"

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
        db.create_all()

create_database()


def render_response(message, status_code, details=None):
    details_html = ''
    if details:
        details_html = '<ul>'
        for error in details:
            details_html += f'<li>{error}</li>'
        details_html += '</ul>'

    # Verifica se a mensagem é um dicionário e formata as mensagens e erros separadamente
    messages_html = ''
    errors_html = ''
    if isinstance(message, dict):
        if 'messages' in message:
            messages_html = '<ul>'
            for msg in message['messages']:
                messages_html += f'<li>{msg}</li>'
            messages_html += '</ul>'
        if 'errors' in message and len(message['errors']) > 0:
            errors_html = '<ul>'
            for error in message['errors']:
                errors_html += f'<li>{error}</li>'
            errors_html += '</ul>'
    else:
        if status_code >= 400:
            errors_html = f'<p>{message}</p>'
        else:
            messages_html = f'<p>{message}</p>'

    html_template = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>API Response</title>
        <link rel="stylesheet" type="text/css" href="{{{{ url_for('static', filename='style.css') }}}}">
        <style>
            body {{
                font-family: Arial, sans-serif;
            }}
            .container {{
                width: 80%;
                margin: 0 auto;
                text-align: center;
            }}
            .message-box, .error-box {{
                margin-top: 20px;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 5px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }}
            .message-box h2, .error-box h2 {{
                margin-top: 0;
            }}
            .message-box {{
                border-color: #4CAF50;
            }}
            .message-box h2 {{
                color: #4CAF50;
            }}
            .error-box {{
                border-color: #f44336;
            }}
            .error-box h2 {{
                color: #f44336;
            }}
            ul {{
                list-style: none;
                padding: 0;
            }}
            ul li {{
                margin: 5px 0;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 5px;
                background-color: #f9f9f9;
            }}
        </style>
    </head>
    <body>
        <div id="header">
            <div class="header-logo">
                <img src="{{{{ url_for('static', filename='transparent_evt_logo.png') }}}}" alt="EVT" style="display:block; margin: 0 auto;">
            </div>
        </div>
        <div class="container">
            <div class="image">
                <img src="{{{{ url_for('static', filename='evt.png') }}}}" alt="EVT">
            </div>
            {f'<div class="message-box"><h2>Mensagens</h2>{messages_html}</div>' if messages_html else ''}
            {f'<div class="error-box"><h2>Erros</h2>{errors_html}</div>' if errors_html else ''}
            {details_html}
        </div>
    </body>
    </html>
    '''
    return render_template_string(html_template), status_code


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

def index():
    user = get_current_user()
    user_id = user['user']['id']
    token = get_or_create_token(user_id, user['user']['mail'])
    return redirect(url_for('relatorio_horas', user_id=user_id, token=token))


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
            return render_response("Invalid credentials"), 401

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
            return render_response("User already exists"), 400
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/aprovar_hora', methods=['GET'])
def aprovar_hora():
    data_id = request.args.get('id')
    token = request.args.get('token')
    is_client = request.args.get('client')
    result = aprovar_ou_reprovar(data_id, 'aprovar', get_current_user(), token, is_client)
    if 'error' in result:
        return jsonify({'message': result['error']}), 400
    else:
        return jsonify({'message': result['message']}), 200

@app.route('/reprovar_hora', methods=['GET'])
def reprovar_hora():
    data_id = request.args.get('id')
    token = request.args.get('token')
    is_client = request.args.get('client')
    result = aprovar_ou_reprovar(data_id, 'reprovar', get_current_user(), token, is_client)
    if 'error' in result:
        return jsonify({'message': result['error']}), 400
    else:
        return jsonify({'message': result['message']}), 200


@app.route('/validar_selecionados', methods=['POST', 'GET'])
@token_required
def validar_selecionados():
    is_client = request.args.get('client')  # Busca a variável is_client dos parâmetros da URL

    if request.method == 'POST':
        selected_entries = request.form.getlist('selected_entries')
    else:
        selected_entries = request.args.get('selected_entries').split(',')

    tipo = request.form.get('tipo_req') if request.method == 'POST' else request.args.get('tipo')
    token = request.args.get('token')
    tipo = tipo + '_selecionados'
    if not selected_entries:
        return render_response("Nenhuma entrada selecionada", 400)
    if tipo not in ['aprovar', 'reprovar', 'aprovar_selecionados', 'reprovar_selecionados']:
        return render_response("Tipo inválido", 400)

    messages = []
    errors = []

    for entry_id in selected_entries:
        result = aprovar_ou_reprovar(entry_id, tipo, get_current_user(), token, is_client)
        if 'error' in result:
            errors.append(result)
        else:
            messages.append(result['message'])

    result = {
        "messages": messages,
        "errors": errors
    }

    return render_response(result, 207 if errors else 200)


def send_email_task(file_content, recipient_emails, project_name, user_id, user_name, allowed_emails):
    logger.info("Tarefa de envio de e-mail iniciada.")
    try:
        logger.info("Chamando função send_email com o seguinte conteúdo:")
        logger.info(file_content)

        # Verifica se recipient_emails é uma string e converte para lista
        if isinstance(recipient_emails, str):
            recipient_emails = [email.strip() for email in recipient_emails.split(',')]

        for email in recipient_emails:
            token = get_or_create_token(user_id, email)
            link = f"{API_URL}relatorio_horas/{user_id}?token={token}"
            email_content = f"{file_content}\n\nPara visualizar as entradas de tempo, acesse o link: <a href='{link}'>Relatório</a>"

            if email.strip() in allowed_emails:
                additional_message = f"\n\nAcesso ao painel de horas: <a href='{API_URL}relatorio_horas?token={token}'>Painel de Horas</a>"
                email_content += f"\n\n{additional_message}"

            send_email(email_content, email.strip(), project_name, user_name)
            logger.info(f"Enviando e-mail para: {email.strip()}")
        logger.info("E-mails enviados com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao enviar e-mails: {e}")


def send_email_task_client(file_content, recipient_email, project_name, user_id, user_name):
    logger.info("Tarefa de envio de e-mail (Cliente) iniciada.")
    try:
        logger.info("Chamando função send_email com o seguinte conteúdo para o cliente:")
        logger.info(file_content)
        token = get_or_create_token(user_id, recipient_email)
        link = f"{API_URL}relatorio_horas_client/{user_id}?token={token}"
        email_content = f"{file_content}\n\nPara visualizar as entradas de tempo, acesse o link: <a href='{link}'>relatório</a>"
        send_email(email_content, recipient_email.strip(), project_name, user_name)
        logger.info(f"E-mail enviado para: {recipient_email.strip()}")
        logger.info("E-mail enviado com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao enviar e-mail para o cliente: {e}")


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

@app.route('/send_email_report_client', methods=['POST'])
def send_email_report_client():
    user_id = request.headers.get('user_id', '')
    logger.info(f"Usuario {user_id} solicitando aprovação de horas.")

    today = datetime.today()
    seven_days_ago = today - timedelta(days=7)
    start_date = seven_days_ago.strftime('%Y-%m-%d')
    end_date = today.strftime('%Y-%m-%d')

    # url = f'{REDMINE_URL}/time_entries.json?user_id={user_id}&from={start_date}&to={end_date}'
    url = f'{REDMINE_URL}/time_entries.json?user_id={user_id}'
    entries_response = requests.get(url, headers={
        'X-Redmine-API-Key': REDMINE_API_KEY,
        'Content-Type': 'application/json'
    }, verify=False)  # Consider replacing verify=False with a valid certificate

    if entries_response.ok:
        time_entries = entries_response.json().get('time_entries', [])
        email_entries = defaultdict(list)

        for entry in time_entries:
            approver_field = next((f for f in entry.get('custom_fields', []) if f['name'] == 'TS - Aprovador - CLI' and f['value']), None)
            if approver_field:
                email_entries[approver_field['value']].append(entry)

        if not email_entries:
            logger.warning('Nenhuma entrada de tempo com o campo TS - Aprovador - CLI encontrada.')
            return jsonify('Nenhuma entrada de tempo com o campo TS - Aprovador - CLI encontrada.'), 400

        for email, entries in email_entries.items():
            unapproved_entries = [entry for entry in entries if any(
                field['name'] == 'TS - Aprovado - EVT' and field['value'] == '0' for field in entry.get('custom_fields', []))]

            if unapproved_entries:
                table_html = create_html_table_mail_client(unapproved_entries, email)
                project_name = unapproved_entries[0]['project']['name']
                user_name = unapproved_entries[0]['user']['name']
                send_email_task_client(table_html, email, project_name, user_id, user_name)
            else:
                logger.info(f'Nenhuma entrada de tempo não aprovada encontrada para o email: {email}')

        return jsonify('Relatórios enviados com sucesso.'), 200
    else:
        logger.error('Erro ao buscar entradas de tempo.')
        return jsonify('Erro ao buscar entradas de tempo.'), 500



@app.route('/send_email_report_client_geral', methods=['POST'])
def send_email_report_client_geral():
    try:
        data = request.get_json()
        time_entries_ids = [entry['id'] for entry in data['entries']]

        time_entries = []
        for entry_id in time_entries_ids:
            url = f'{REDMINE_URL}/time_entries/{entry_id}.json'
            response = requests.get(url, headers={
                'X-Redmine-API-Key': REDMINE_API_KEY,
                'Content-Type': 'application/json'
            }, verify=False)

            if response.ok:
                time_entry = response.json().get('time_entry', {})
                time_entries.append(time_entry)
            else:
                logger.error(f"Erro ao buscar entrada de tempo com ID {entry_id}: {response.status_code}")
                return jsonify(f"Erro ao buscar entrada de tempo com ID {entry_id}", 500)

        email_entries = defaultdict(list)

        for entry in time_entries:
            approver_field = next(
                (f for f in entry.get('custom_fields', []) if f['name'] == 'TS - Aprovador - CLI' and f['value']), None)
            if approver_field:
                email_entries[approver_field['value']].append(entry)

        if not email_entries:
            logger.warning('Nenhuma entrada de tempo com o campo TS - Aprovador - CLI encontrada.')
            return jsonify('Nenhuma entrada de tempo com o campo TS - Aprovador - CLI encontrada.'), 400

        for email, entries in email_entries.items():
            unapproved_entries = [entry for entry in entries if any(
                field['name'] == 'TS - Aprovado - EVT' and field['value'] == '0' for field in
                entry.get('custom_fields', []))]

            if unapproved_entries:
                table_html = create_html_table_mail_client(unapproved_entries, email)
                project_name = unapproved_entries[0]['project']['name']
                user_name = unapproved_entries[0]['user']['name']
                user_id = unapproved_entries[0]['user']['id']
                send_email_task_client(table_html, email, project_name, user_id, user_name)
            else:
                logger.info(f'Nenhuma entrada de tempo não aprovada encontrada para o email: {email}')

        return jsonify({"message": "Relatórios enviados com sucesso."}), 200
    except Exception as e:
        logger.error(f"Erro ao enviar relatórios por email: {e}")
        return jsonify("Erro ao enviar relatórios por email", 500)


@app.route('/send_email_report', methods=['POST'])
def send_email_report():
    user_id = request.headers.get('user_id', '')
    logger.info(f"Usuario {user_id} solicitando aprovação de horas.")
    allowed_emails = request.headers.get('allowed_emails', '').split(',')
    today = datetime.today()
    seven_days_ago = today - timedelta(days=7)
    start_date = seven_days_ago.strftime('%Y-%m-%d')
    end_date = today.strftime('%Y-%m-%d')

    #url = f'{REDMINE_URL}/time_entries.json?user_id={user_id}&from={start_date}&to={end_date}'
    url = f'{REDMINE_URL}/time_entries.json?user_id={user_id}'
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
            return jsonify('Nenhuma entrada de tempo não aprovada encontrada.'), 400

        table_html = create_html_table_mail(unapproved_entries)
        recipient_emails = request.headers.get('recipient', '').split(',')
        if not recipient_emails or recipient_emails == ['']:
            logger.error('Nenhum e-mail de destinatário fornecido.')
            return jsonify('Nenhum e-mail de destinatário fornecido.'), 400
            # return render_response('Nenhum e-mail de destinatário fornecido.'), 400
        project_name = unapproved_entries[0]['project']['name']
        user_name = unapproved_entries[0]['user']['name']
        send_email_task(table_html, recipient_emails, project_name, user_id, user_name, allowed_emails)
        return jsonify('Relatório enviado com sucesso.'), 200
        # return render_response('Relatório enviado com sucesso.'), 200
    else:
        logger.error('Erro ao buscar entradas de tempo.')
        return jsonify('Erro ao buscar entradas de tempo.'), 500
        # return render_response('Erro ao buscar entradas de tempo.'), 500


@app.route('/send_unitary_report', methods=['POST'])
def send_unitary_report():
    entry_id = request.headers.get('id', '')
    if not entry_id:
        return jsonify('ID de entrada não fornecido.'), 400

    recipient_emails = request.headers.get('recipient', '').split(',')
    if not recipient_emails or recipient_emails == ['']:
        logger.error('Nenhum e-mail de destinatário fornecido.')
        return jsonify('Nenhum e-mail de destinatário fornecido.'), 400

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

        return jsonify('Relatório enviado com sucesso.'), 200

    except Exception as e:
        logger.error(f"Erro ao processar a solicitação: {e}")
        return jsonify('Erro ao processar a solicitação.'), 500

@app.route('/send_unitary_report_new', methods=['POST'])
def send_unitary_report_new():
    entry_id = request.headers.get('id', '')
    if not entry_id:
        return jsonify('ID de entrada não fornecido.'), 400

    recipient_emails = request.headers.get('recipient', '').split(',')
    if not recipient_emails or recipient_emails == ['']:
        logger.error('Nenhum e-mail de destinatário fornecido.')
        return jsonify('Nenhum e-mail de destinatário fornecido.'), 400

    try:
        # Realiza a busca na API do Redmine para obter as informações da entrada de tempo
        status_code, response = get_time_entry(entry_id)
        if status_code == 200:
            time_entry = response.get('time_entry', {})
            project_name = time_entry['project']['name']
            user_name = time_entry['user']['name']
            user_id = time_entry['user']['id']
            allowed_emails = request.headers.get('allowed_emails', '').split(',')
            table_html = create_html_unitary_table(time_entry)
            for email in recipient_emails:
                token = get_or_create_token(time_entry['user']['id'], email)
                link = f"{API_URL}relatorio_horas/{time_entry['user']['id']}?token={token}"
                send_email_task(table_html, email.strip(), project_name, user_id, user_name, allowed_emails)

            return jsonify('Relatório enviado com sucesso.'), 200

        else:
            logger.error(f"Erro ao buscar entrada de tempo: {status_code} - {response}")
            return jsonify('Erro ao buscar entrada de tempo.'), 500

    except Exception as e:
        logger.error(f"Erro ao processar a solicitação: {e}")
        return jsonify('Erro ao processar a solicitação.'), 500


@app.route('/aprovar_todos', methods=['GET'])
def aprovar_todos():
    token = request.args.get('token')
    entries = request.args.get('entries')
    is_client = request.args.get('client')
    entry_ids = entries.split(',') if entries else []
    return atualizar_todas_entradas(aprovacao=True, entry_ids=entry_ids, token=token, is_client=is_client)

@app.route('/reprovar_todos', methods=['GET'])
def reprovar_todos():
    token = request.args.get('token')
    entries = request.args.get('entries')
    is_client = request.args.get('client')
    entry_ids = entries.split(',') if entries else []
    return atualizar_todas_entradas(aprovacao=False, entry_ids=entry_ids, token=token, is_client=is_client)


def atualizar_todas_entradas(aprovacao, entry_ids, token, is_client):
    user = get_current_user()
    errors = []

    for entry_id in entry_ids:
        status_code, response = get_time_entry(entry_id)
        if status_code == 200:
            time_entry = response.get('time_entry', {})
            custom_fields = time_entry.get('custom_fields', [])

            data_original = time_entry.get('spent_on')
            nova_data = (datetime.now() - timedelta(days=4)).strftime('%Y-%m-%d')
            data_atual = datetime.now().strftime('%Y-%m-%d')

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
                    field['value'] = data_atual if aprovacao else ''
                if field.get('name') == 'TS - Aprovador - EVT':
                    field['value'] = get_recipient_by_token(token) if aprovacao else ''

            update_status, update_response = update_time_entry(entry_id, custom_fields)
            if update_status in [200, 204]:
                restaurar_data_original(entry_id, data_original)
                log_approval_rejection(entry_id, time_entry['spent_on'], time_entry['hours'],
                                       'aprovar' if aprovacao else 'reprovar', token)
            else:
                restaurar_data_original(entry_id, data_original)
                errors.append({
                    'id': entry_id,
                    'status': update_status,
                    'response': update_response
                })
        else:
            errors.append({
                'id': entry_id,
                'status': status_code,
                'response': response
            })

    if errors:
        return render_response("Some entries failed to update", 207, details=errors)

    return render_response(f"Todas as horas foram {'aprovadas' if aprovacao else 'reprovadas'}!", 200)


def get_recipient_by_token(token):
    access_token = AccessToken.query.filter_by(token=token).first()
    return access_token.recipient_email if access_token else None


def create_html_unitary_table(entry):
    table = '''
    <form id="time_entries_form" method="get" action="https://timesheetqas.evtit.com/validar_selecionados">
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

def create_html_table_mail_client(time_entries, recipient):
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
        approver_cli = next(
            (field['value'] for field in entry['custom_fields'] if field['name'] == 'TS - Aprovador - CLI'), '')

        if approver_cli == recipient:
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
        thirty_days_ago = today - timedelta(days=90)
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

            table_html = create_html_table(time_entries)
            # Obtém o token da URL atual
            user = get_current_user()
            user_id = user['user']['id']
            token = get_or_create_token(user_id, user['user']['mail'])
            # Constrói a lista de IDs das entradas
            entry_ids = ','.join([str(entry['id']) for entry in time_entries])
            is_client = 1 if 'client' in request.full_path else 0
            # Extrai usuários e projetos para os filtros
            usuarios = {entry['user']['name'] for entry in time_entries}
            projetos = {entry['project']['name'] for entry in time_entries}

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

                    function filterBySelect() {{
                        var userSelect = document.getElementById("userSelect").value.toUpperCase();
                        var projectSelect = document.getElementById("projectSelect").value.toUpperCase();
                        var table = document.getElementById("time_entries_table");
                        var tr = table.getElementsByTagName("tr");
                        for (var i = 1; i < tr.length; i++) {{
                            tr[i].style.display = "none";
                            var userTd = tr[i].getElementsByTagName("td")[2];
                            var projectTd = tr[i].getElementsByTagName("td")[4];
                            if (userTd && projectTd) {{
                                var userValue = userTd.textContent || userTd.innerText;
                                var projectValue = projectTd.textContent || projectTd.innerText;
                                if ((userSelect === "ALL" || userValue.toUpperCase() === userSelect) &&
                                    (projectSelect === "ALL" || projectValue.toUpperCase() === projectSelect)) {{
                                    tr[i].style.display = "";
                                }}
                            }}
                        }}
                    }}

                    function toggleFieldset(legend) {{
                        var fieldset = legend.parentElement;
                        fieldset.classList.toggle('collapsed');
                        var div = fieldset.querySelector('div');
                        var arrow = legend.querySelector('.arrow');
                        if (fieldset.classList.contains('collapsed')) {{
                            div.style.display = 'none';
                            arrow.innerHTML = '▼';  // Seta para a direita
                        }} else {{
                            div.style.display = 'block';
                            arrow.innerHTML = '▶';  // Seta para baixo
                        }}
                    }}

                    function toggleAll(source) {{
                        checkboxes = document.getElementsByName('selected_entries');
                        for(var i=0, n=checkboxes.length;i<n;i++) {{
                            checkboxes[i].checked = source.checked;
                        }}
                    }}

                    function getFilteredTableData() {{
                        var table = document.getElementById("time_entries_table");
                        var tr = table.getElementsByTagName("tr");
                        var data = [];
                        var checkboxes = document.querySelectorAll('input[name="selected_entries"]:checked');

                        if (checkboxes.length > 0) {{
                            for (var checkbox of checkboxes) {{
                                var row = checkbox.closest("tr");
                                var td = row.getElementsByTagName("td");
                                var entry = {{
                                    id: td[0].querySelector("input").value,
                                    date: td[1].textContent,
                                    user: td[2].textContent,
                                    activity: td[3].textContent,
                                    project: td[4].textContent,
                                    comments: td[5].textContent,
                                    start_time: td[6].textContent,
                                    end_time: td[7].textContent,
                                    hours: td[8].textContent
                                }};
                                data.push(entry);
                            }}
                        }} else {{
                            for (var i = 1; i < tr.length; i++) {{
                                if (tr[i].style.display !== "none") {{
                                    var td = tr[i].getElementsByTagName("td");
                                    var entry = {{
                                        id: td[0].querySelector("input").value,
                                        date: td[1].textContent,
                                        user: td[2].textContent,
                                        activity: td[3].textContent,
                                        project: td[4].textContent,
                                        comments: td[5].textContent,
                                        start_time: td[6].textContent,
                                        end_time: td[7].textContent,
                                        hours: td[8].textContent
                                    }};
                                    data.push(entry);
                                }}
                            }}
                        }}

                        return data;
                    }}

                    function sendFilteredData() {{
                        var data = getFilteredTableData();
                        fetch('/send_email_report_client_geral', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json'
                            }},
                            body: JSON.stringify({{ entries: data }})
                        }})
                        .then(response => response.json())
                        .then(data => {{
                            console.log('Success:', data);
                        }})
                        .catch((error) => {{
                            console.error('Error:', error);
                        }});
                    }}
                </script>
              <style>
    .container {{
        display: flex;
        flex-direction: column;
        margin-top: 0; /* Remove qualquer margem superior */
    }}
    .filters-container {{
        display: flex;
        justify-content: flex-start; /* Alinha os itens no início */
        margin-bottom: 10px;
        width: 100%; /* Garante que ocupe a largura total */
    }}
    fieldset {{
        border: none;
        margin: 0; /* Remove margem */
        padding: 0; /* Remove padding */
    }}
    .filters {{
        display: flex;
        align-items: center;
        gap: 10px;
        margin: 0; /* Remove margem */
        padding: 0; /* Remove padding */
    }}
    .table-container {{
        width: 100%;
        overflow-x: auto; /* Adiciona rolagem horizontal */
        overflow-y: auto; /* Adiciona rolagem vertical */
        max-height: 400px; /* Define uma altura máxima para a tabela */
    }}
    .btn-group {{
        display: flex;
        justify-content: center;
        margin-top: 20px;
    }}
    .filters label, .legend-button {{
        color: black;
    }}
    .btn-relatorio {{
        background-color: #1E90FF; /* Cor azul padrão */
        color: white; /* Texto branco */
        width: 200px; /* Ajuste para corresponder ao tamanho dos outros botões */
        border-radius: 5px; /* Bordas arredondadas */
        border: none; /* Remover borda */
        transition: background-color 0.3s; /* Suavização da transição de cor */
    }}
    .btn-relatorio:hover {{
        background-color: #63B8FF; /* Azul claro ao passar o mouse */
    }}
    table {{
        width: 100%;
    }}
</style>

            </head>
            <body>
                <div id="header">
                    <div class="header-logo">
                        <img src="{{{{ url_for('static', filename='transparent_evt_logo.png') }}}}" alt="EVT">
                        <h1>EVT - Aprovação de Horas</h1>
                    </div>
                </div>
                <div class="container">
                    <div class="filters-container">
                        <form id="time_entries_form" method="get" action="https://timesheetqas.evtit.com/validar_selecionados?client={is_client}">
                            <fieldset class="collapsible">
                                <legend class="legend-text" onclick="toggleFieldset(this);">
                                    <span class="legend-button">
                                        <span class="arrow">▶</span>
                                        Filtros
                                    </span>
                                </legend>
                                <div>
                                    <label for="filterInput">Buscar:</label>
                                    <input type="text" id="filterInput" onkeyup="filterTable()" placeholder="Digite para buscar...">
                                    <label for="userSelect">Usuário:</label>
                                    <select id="userSelect" onchange="filterBySelect()">
                                        <option value="ALL">Todos</option>
                                        {''.join([f'<option value="{usuario.upper()}">{usuario}</option>' for usuario in sorted(usuarios)])}
                                    </select>
                                    <label for="projectSelect">Projeto:</label>
                                    <select id="projectSelect" onchange="filterBySelect()">
                                        <option value="ALL">Todos</option>
                                        {''.join([f'<option value="{projeto.upper()}">{projeto}</option>' for projeto in sorted(projetos)])}
                                    </select>
                                </div>
                            </fieldset>
                        </form>
                    </div>
                    <div class="table-container">
                        {table_html}
                    </div>
                    <div id="all-actions" class="btn-group">
                        <a href="{API_URL}aprovar_todos?token={token}&entries={entry_ids}&client={is_client}" class="btn btn-approve" target="_blank">Aprovar Todos</a>
                        <a href="{API_URL}reprovar_todos?token={token}&entries={entry_ids}&client={is_client}" class="btn btn-reject" target="_blank">Reprovar Todos</a>
                        <button type="button" onclick="sendFilteredData()" class="btn-relatorio">Enviar Relatório - Cliente</button>
                    </div>
                    <div id="selected-actions" class="btn-group">
                        <button type="button" id="approve-selected" class="btn btn-approve" data-action="aprovar">Aprovar Selecionados</button>
                        <button type="button" id="reject-selected" class="btn btn-reject" data-action="reprovar">Reprovar Selecionados</button>
                        <button type="button" onclick="sendFilteredData()" class="btn-relatorio">Enviar Relatório - Cliente</button>
                    </div>
                </div>
                <script src="{{{{ url_for('static', filename='script.js') }}}}"></script>
            </body>
            </html>
            '''

            return render_template_string(html_template)
        else:
            logger.error(f"Erro ao buscar entradas de tempo: {entries_response.status_code}")
            return render_response("Erro ao buscar entradas de tempo", 500)
    except Exception as e:
        logger.error(f"Erro ao gerar a página HTML: {e}")
        return render_response("Erro ao gerar a página HTML", 500)

@app.route('/relatorio_horas/<int:user_id>', methods=['GET'])
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
            return render_response("Usuário não encontrado", 404)

        user = user_response.json()
        user_name = user['user']['firstname'] + ' ' + user['user']['lastname']

        # Obter parâmetros de filtro
        project_id = request.args.get('project_id')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        is_client = 1 if 'client' in request.full_path else 0

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
            # Obtém o token da URL atual

            token = request.args.get('token')
            # Constrói a lista de IDs das entradas
            entry_ids = ','.join([str(entry['id']) for entry in unapproved_entries])

            # Extrai usuários e projetos para os filtros
            usuarios = {entry['user']['name'] for entry in unapproved_entries}
            projetos = {entry['project']['name'] for entry in unapproved_entries}

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
                    function toggleFieldset(legend) {{
                        var fieldset = legend.parentElement;
                        fieldset.classList.toggle('collapsed');
                        var div = fieldset.querySelector('div');
                        var arrow = legend.querySelector('.arrow');
                        if (fieldset.classList.contains('collapsed')) {{
                            div.style.display = 'none';
                            arrow.innerHTML = '▼';  // Seta para a direita
                        }} else {{
                            div.style.display = 'block';
                            arrow.innerHTML = '▶';  // Seta para baixo
                        }}
                    }}

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

                    function filterBySelect() {{
                        var userSelect = document.getElementById("userSelect").value.toUpperCase();
                        var projectSelect = document.getElementById("projectSelect").value.toUpperCase();
                        var table = document.getElementById("time_entries_table");
                        var tr = table.getElementsByTagName("tr");
                        for (var i = 1; i < tr.length; i++) {{
                            tr[i].style.display = "none";
                            var userTd = tr[i].getElementsByTagName("td")[2];
                            var projectTd = tr[i].getElementsByTagName("td")[4];
                            if (userTd && projectTd) {{
                                var userValue = userTd.textContent || userTd.innerText;
                                var projectValue = projectTd.textContent || projectTd.innerText;
                                if ((userSelect === "ALL" || userValue.toUpperCase() === userSelect) &&
                                    (projectSelect === "ALL" || projectValue.toUpperCase() === projectSelect)) {{
                                    tr[i].style.display = "";
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

                    function getFilteredTableData() {{
                        var table = document.getElementById("time_entries_table");
                        var tr = table.getElementsByTagName("tr");
                        var data = [];
                        var checkboxes = document.querySelectorAll('input[name="selected_entries"]:checked');

                        if (checkboxes.length > 0) {{
                            for (var checkbox of checkboxes) {{
                                var row = checkbox.closest("tr");
                                var td = row.getElementsByTagName("td");
                                var entry = {{
                                    id: td[0].querySelector("input").value,
                                    date: td[1].textContent,
                                    user: td[2].textContent,
                                    activity: td[3].textContent,
                                    project: td[4].textContent,
                                    comments: td[5].textContent,
                                    start_time: td[6].textContent,
                                    end_time: td[7].textContent,
                                    hours: td[8].textContent
                                }};
                                data.push(entry);
                            }}
                        }} else {{
                            for (var i = 1; i < tr.length; i++) {{
                                if (tr[i].style.display !== "none") {{
                                    var td = tr[i].getElementsByTagName("td");
                                    var entry = {{
                                        id: td[0].querySelector("input").value,
                                        date: td[1].textContent,
                                        user: td[2].textContent,
                                        activity: td[3].textContent,
                                        project: td[4].textContent,
                                        comments: td[5].textContent,
                                        start_time: td[6].textContent,
                                        end_time: td[7].textContent,
                                        hours: td[8].textContent
                                    }};
                                    data.push(entry);
                                }}
                            }}
                        }}

                        return data;
                    }}

                    function sendFilteredData() {{
                        var data = getFilteredTableData();
                        fetch('/send_email_report_client_geral', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json'
                            }},
                            body: JSON.stringify({{ entries: data }})
                        }})
                        .then(response => response.json())
                        .then(data => {{
                            console.log('Success:', data);
                        }})
                        .catch((error) => {{
                            console.error('Error:', error);
                        }});
                    }}
                </script>
                <style>
    .container {{
        display: flex;
        flex-direction: column;
        align-items: center;
    }}
    .filters-container {{
        display: flex;
        justify-content: center;
        margin-bottom: 10px;
    }}
    fieldset {{
        border: none;
        margin-top: -510px;
        margin-right: 1110px;
    }}
    .filters {{
        display: flex;
        align-items: center;
        gap: 10px;
    }}
    .table-container {{
        margin-top: -480px;
        width: 100%;
    }}
    .btn-group {{
        display: flex;
        justify-content: center;
        margin-top: 20px;
    }}
    .filters label, .legend-button {{
        color: black;
    }}
    .btn-relatorio {{
        background-color: #1E90FF; /* Cor azul padrão */
        color: white; /* Texto branco */
        width: 200px; /* Ajuste para corresponder ao tamanho dos outros botões */
        border-radius: 5px; /* Bordas arredondadas */
        border: none; /* Remover borda */
        transition: background-color 0.3s; /* Suavização da transição de cor */
    }}
    .btn-relatorio:hover {{
        background-color: #63B8FF; /* Azul claro ao passar o mouse */
    }}
</style>
            </head>
            <body>
                <div id="header">
                    <div class="header-logo">
                        <img src="{{{{ url_for('static', filename='transparent_evt_logo.png') }}}}" alt="EVT">
                        <h1>EVT - Aprovação de Horas - {user_name}</h1>
                    </div>
                </div>
                <div class="container">
                    <div class="filters-container">
                        <form id="time_entries_form" method="get" action="https://timesheetqas.evtit.com/validar_selecionados?client={is_client}">
                            <fieldset class="collapsible">
                                <legend onclick="toggleFieldset(this);">
                                    <span class="legend-button">
                                        <span class="arrow">▶</span>
                                        Filtros
                                    </span>
                                </legend>
                                <div>
                                    <label for="filterInput">Buscar:</label>
                                    <input type="text" id="filterInput" onkeyup="filterTable()" placeholder="Digite para buscar...">
                                    <label for="userSelect">Usuário:</label>
                                    <select id="userSelect" onchange="filterBySelect()">
                                        <option value="ALL">Todos</option>
                                        {''.join([f'<option value="{usuario.upper()}">{usuario}</option>' for usuario in sorted(usuarios)])}
                                    </select>
                                    <label for="projectSelect">Projeto:</label>
                                    <select id="projectSelect" onchange="filterBySelect()">
                                        <option value="ALL">Todos</option>
                                        {''.join([f'<option value="{projeto.upper()}">{projeto}</option>' for projeto in sorted(projetos)])}
                                    </select>
                                </div>
                            </fieldset>
                        </form>
                    </div>
                    <div class="table-container">
                        {table_html}
                    </div>
                    <div id="all-actions" class="btn-group">
                        <a href="{API_URL}aprovar_todos?token={token}&entries={entry_ids}&client={is_client}" class="btn btn-approve" target="_blank">Aprovar Todos</a>
                        <a href="{API_URL}reprovar_todos?token={token}&entries={entry_ids}&client={is_client}" class="btn btn-reject" target="_blank">Reprovar Todos</a>
                        <button type="button" onclick="sendFilteredData()" class="btn-relatorio">Enviar Relatório - Cliente</button>
                    </div>
                    <div id="selected-actions" class="btn-group">
                        <button type="button" id="approve-selected" class="btn btn-approve" data-action="aprovar">Aprovar Selecionados</button>
                        <button type="button" id="reject-selected" class="btn btn-reject" data-action="reprovar">Reprovar Selecionados</button>
                        <button type="button" onclick="sendFilteredData()" class="btn-relatorio">Enviar Relatório Selecionados - Cliente</button>
                    </div>
                </div>
                <script src="{{{{ url_for('static', filename='script.js') }}}}"></script>
            </body>
            </html>
            '''

            return render_template_string(html_template)
        else:
            logger.error(f"Erro ao buscar entradas de tempo: {entries_response.status_code}")
            return render_response("Erro ao buscar entradas de tempo", 500)
    except Exception as e:
        logger.error(f"Erro ao gerar a página HTML: {e}")
        return render_response("Erro ao gerar a página HTML", 500)

@app.route('/relatorio_horas_client/<int:user_id>', methods=['GET'])
def relatorio_horas_client(user_id):
    try:
        # Faz uma requisição para obter o usuário pelo ID fornecido na URL
        user_url = f'{REDMINE_URL}/users/{user_id}.json'
        user_response = requests.get(user_url, headers={
            'X-Redmine-API-Key': REDMINE_API_KEY,
            'Content-Type': 'application/json'
        }, verify=False)

        if not user_response.ok:
            logger.error(f"Erro ao buscar usuário com ID {user_id}: {user_response.status_code}")
            return render_response("Usuário não encontrado", 404)

        user = user_response.json()
        user_name = user['user']['firstname'] + ' ' + user['user']['lastname']

        # Obter parâmetros de filtro
        project_id = request.args.get('project_id')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        is_client = 1 if 'client' in request.full_path else 0
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
            # Filtra as entradas de tempo para incluir apenas aquelas que não foram aprovadas e têm o destinatário correto
            time_entries = entries_response.json().get('time_entries', [])
            unapproved_entries = [entry for entry in time_entries if any(
                field['name'] == 'TS - Aprovado - EVT' and field['value'] == '0' for field in entry.get('custom_fields', []))
                and any(field['name'] == 'TS - Aprovador - CLI' for field in entry.get('custom_fields', []))
            ]

            # Agrupar entradas por destinatário
            email_entries = defaultdict(list)
            for entry in unapproved_entries:
                recipient = next((field['value'] for field in entry['custom_fields'] if field['name'] == 'TS - Aprovador - CLI'), None)
                if recipient:
                    email_entries[recipient].append(entry)

            if not unapproved_entries:
                logger.warning(
                    f"Nenhuma entrada de tempo não aprovada encontrada para o usuário ID {user_id} no período de {start_date} a {end_date}")

            token = request.args.get('token')
            token_email = get_email_from_token(token)  # Obtendo o e-mail associado ao token

            for recipient, entries in email_entries.items():
                # Validação do e-mail do token com o recipient
                if token_email != recipient:
                    logger.warning(f'Token não autorizado para o e-mail: {recipient} ')
                    continue

                table_html = create_html_table_client(entries, recipient)
                # Constrói a lista de IDs das entradas
                entry_ids = ','.join([str(entry['id']) for entry in entries])

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
                            <h1>EVT - Aprovação de Horas - {user_name}</h1>
                        </div>
                    </div>
                    <div class="container">
                        <form id="time_entries_form" method="get" action="https://timesheetqas.evtit.com/validar_selecionados?client={is_client}">
                            <div class="filters">
                                <label for="filterInput">Buscar:</label>
                                <input type="text" id="filterInput" onkeyup="filterTable()" placeholder="Digite para buscar...">
                            </div>
                            {table_html}
                            <div id="all-actions" class="btn-group">
                                <a href="{API_URL}aprovar_todos?token={token}&entries={entry_ids}&client={is_client}" class="btn btn-approve" target="_blank">Aprovar Todos</a>
                                <a href="{API_URL}reprovar_todos?token={token}&entries={entry_ids}&client={is_client}" class="btn btn-reject" target="_blank">Reprovar Todos</a>
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
            return render_response("Erro ao buscar entradas de tempo", 500)
    except Exception as e:
        logger.error(f"Erro ao gerar a página HTML: {e}")
        return render_response("Erro ao gerar a página HTML", 500)


def create_html_table(time_entries):
    table = '''
    <div style="overflow-x:auto;">
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
        <th>Aprovado</th>
        <th>Ações</th>
      </tr>
    </thead>
    <tbody>
    '''

    total_hours = 0  # Variável para somar as horas
    approved_hours = 0  # Variável para somar as horas aprovadas
    unapproved_hours = 0  # Variável para somar as horas não aprovadas

    for entry in time_entries:
        hora_inicial = next(
            (field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora inicial (HH:MM)'), '')
        hora_final = next((field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora final (HH:MM)'),
                          '')
        project_name = entry['project']['name'] if 'project' in entry else 'N/A'
        user_id = entry['user']['id']
        user_email = 'teste@teste.com'  # tornar dinâmico após ajustar o plugin
        token = request.args.get('token')
        is_client = 1 if 'client' in request.full_path else 0
        if token is None:
            token = get_or_create_token(user_id, user_email)

        total_hours += entry['hours']  # Soma as horas da entrada atual

        approved = any(
            field['name'] == 'TS - Aprovado - EVT' and (field['value'] == '1' or field['value'] == '0') for field in
            entry['custom_fields'])
        if approved:
            approved_hours += entry['hours']
        else:
            unapproved_hours += entry['hours']

        disable_attr = 'disabled' if approved else ''
        aprovado = 'Sim' if approved else 'Não'

        table += f'''
        <tr id="entry-row-{entry['id']}">
          <td><input type="checkbox" name="selected_entries" value="{entry['id']}" {disable_attr}></td>
          <td>{entry['spent_on']}</td>
          <td>{entry['user']['name']}</td>
          <td>{entry['activity']['name']}</td>
          <td>{project_name}</td>
          <td>{entry['comments']}</td>
          <td>{hora_inicial}</td>
          <td>{hora_final}</td>
          <td>{entry['hours']}</td>
          <td>{aprovado}</td>
          <td>
            <a href="#" onclick="approveHour({entry['id']}, '{token}', {is_client})" class="btn btn-approve-table" style="pointer-events:{'none' if approved else 'auto'};opacity:{'0.5' if approved else '1'};">Aprovar</a>
            <a href="#" onclick="rejectHour({entry['id']}, '{token}', {is_client})" class="btn btn-reject-table" style="pointer-events:{'none' if approved else 'auto'};opacity:{'0.5' if approved else '1'};">Reprovar</a>
          </td>
        </tr>
        '''

    # Adiciona a linha com o total de horas no final da tabela
    table += f'''
    <tr>
      <td colspan="8" style="text-align: right; font-weight: bold;">Total de Horas:</td>
      <td colspan="2" style="font-weight: bold;">{total_hours}</td>
    </tr>
    <tr>
      <td colspan="8" style="text-align: right; font-weight: bold;">Total de Horas Aprovadas:</td>
      <td colspan="2" style="font-weight: bold;">{approved_hours}</td>
    </tr>
    <tr>
      <td colspan="8" style="text-align: right; font-weight: bold;">Total de Horas Não Aprovadas:</td>
      <td colspan="2" style="font-weight: bold;">{unapproved_hours}</td>
    </tr>
    '''

    table += '''
    </tbody>
    </table>
    </div>
    <br>
    '''

    table += f'''
    <script>
      function approveHour(entryId, token, isClient) {{
        fetch("{API_URL}aprovar_hora?id=" + entryId + "&token=" + token + "&client=" + isClient)
        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
        .then(result => {{
          const status = result.status;
          const body = result.body;
          if (status === 200) {{
            alert(body.message);
            disableRow(entryId);
          }} else {{
            alert(body.message);
          }}
        }})
        .catch(error => {{
          console.error('Erro:', error);
          alert('Erro ao aprovar hora.');
        }});
      }}

      function rejectHour(entryId, token, isClient) {{
        fetch("{API_URL}reprovar_hora?id=" + entryId + "&token=" + token + "&client=" + isClient)
        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
        .then(result => {{
          const status = result.status;
          const body = result.body;
          if (status === 200) {{
            alert(body.message);
            disableRow(entryId);
          }} else {{
            alert(body.message);
          }}
        }})
        .catch(error => {{
          console.error('Erro:', error);
          alert('Erro ao reprovar hora.');
        }});
      }}

      function disableRow(entryId) {{
        var row = document.getElementById("entry-row-" + entryId);
        var checkBox = row.querySelector('input[type="checkbox"]');
        var buttons = row.querySelectorAll('a');

        if (checkBox) {{
          checkBox.disabled = true;
        }}
        buttons.forEach(button => {{
          button.style.pointerEvents = 'none';
          button.style.opacity = '0.5';
        }});
      }}

      function toggleAll(source) {{
        var checkboxes = document.getElementsByName('selected_entries');
        for (var i = 0, n = checkboxes.length; i < n; i++) {{
          if (!checkboxes[i].disabled) {{
            checkboxes[i].checked = source.checked;
          }}
        }}
      }}
    </script>
    '''

    return table


def create_html_table_client(time_entries, recipient):
    table = '''
    <div style="overflow-x:auto;">
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
        <th>Aprovado</th>
        <th>Ações</th>
      </tr>
    </thead>
    <tbody>
    '''

    for entry in time_entries:
        approver_cli = next(
            (field['value'] for field in entry['custom_fields'] if field['name'] == 'TS - Aprovador - CLI'), '')

        if approver_cli == recipient:
            hora_inicial = next(
                (field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora inicial (HH:MM)'), '')
            hora_final = next(
                (field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora final (HH:MM)'),
                '')
            project_name = entry['project']['name'] if 'project' in entry else 'N/A'
            is_client = 1 if 'client' in request.full_path else 0

            approved = any(
                field['name'] == 'TS - Aprovado - CLI' and (field['value'] == '1' or field['value'] == '0') for field
                in entry['custom_fields'])
            disable_attr = 'disabled' if approved else ''
            aprovado = 'Sim' if approved else 'Não'

            table += f'''
            <tr id="entry-row-{entry['id']}">
              <td><input type="checkbox" name="selected_entries" value="{entry['id']}" {disable_attr}></td>
              <td>{entry['spent_on']}</td>
              <td>{entry['user']['name']}</td>
              <td>{entry['activity']['name']}</td>
              <td>{project_name}</td>
              <td>{entry['comments']}</td>
              <td>{hora_inicial}</td>
              <td>{hora_final}</td>
              <td>{entry['hours']}</td>
              <td>{aprovado}</td>
              <td>
                <a href="#" onclick="approveHour({entry['id']}, '{request.args.get('token')}', {is_client})" class="btn btn-approve-table" style="pointer-events:{'none' if approved else 'auto'};opacity:{'0.5' if approved else '1'};">Aprovar</a>
                <a href="#" onclick="rejectHour({entry['id']}, '{request.args.get('token')}', {is_client})" class="btn btn-reject-table" style="pointer-events:{'none' if approved else 'auto'};opacity:{'0.5' if approved else '1'};">Reprovar</a>
              </td>
            </tr>
            '''

    table += '''
    </tbody>
    </table>
    </div>
    <br>
    '''

    table += f'''
    <script>
      function approveHour(entryId, token, isClient) {{
        fetch("{API_URL}aprovar_hora?id=" + entryId + "&token=" + token + "&client=" + isClient)
        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
        .then(result => {{
          const status = result.status;
          const body = result.body;
          if (status === 200) {{
            alert(body.message);
            disableRow(entryId);
          }} else {{
            alert(body.message);
          }}
        }})
        .catch(error => {{
          console.error('Erro:', error);
          alert('Erro ao aprovar hora.');
        }});
      }}

      function rejectHour(entryId, token, isClient) {{
        fetch("{API_URL}reprovar_hora?id=" + entryId + "&token=" + token + "&client=" + isClient)
        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
        .then(result => {{
          const status = result.status;
          const body = result.body;
          if (status === 200) {{
            alert(body.message);
            disableRow(entryId);
          }} else {{
            alert(body.message);
          }}
        }})
        .catch(error => {{
          console.error('Erro:', error);
          alert('Erro ao reprovar hora.');
        }});
      }}

      function disableRow(entryId) {{
        var row = document.getElementById("entry-row-" + entryId);
        var checkBox = row.querySelector('input[type="checkbox"]');
        var buttons = row.querySelectorAll('a');

        if (checkBox) {{
          checkBox.disabled = true;
        }}
        buttons.forEach(button => {{
          button.style.pointerEvents = 'none';
          button.style.opacity = '0.5';
        }});
      }}
    </script>
    '''

    return table


def get_time_entry(time_entry_id):
    url = f"{REDMINE_URL}/time_entries/{time_entry_id}.json"
    headers = {'X-Redmine-API-Key': REDMINE_API_KEY}
    response = requests.get(url, headers=headers, verify=False)

    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, {"error": "Invalid JSON response"}

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
                if any("Apontamento retroativo" in error for error in error_message) or any("Foi detectado um apontamento" in error for error in error_message) or any("semana" in error for error in error_message):
                    nova_data = (datetime.strptime(nova_data, '%Y-%m-%d') + timedelta(days=5)).strftime('%Y-%m-%d')
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


def aprovar_ou_reprovar(entry_id, tipo, user, token, is_client):
    status_code, response = get_time_entry(entry_id)
    if status_code == 200:
        time_entry = response.get('time_entry', {})
        custom_fields = time_entry.get('custom_fields', [])
        data_original = time_entry.get('spent_on')
        nova_data = (datetime.now() - timedelta(days=4)).strftime('%Y-%m-%d')
        data_atual = datetime.now().strftime('%Y-%m-%d')
        alterar_status, alterar_response = alterar_data_temporariamente(entry_id, nova_data)
        if is_client == '0':
            if alterar_status not in [200, 204]:
                return {"error": "Failed to temporarily change date", "details": alterar_response}
            for field in custom_fields:
                if field.get('name') == 'TS - Aprovado - EVT':
                    field['value'] = '1' if tipo in ['aprovar', 'aprovar_selecionados'] else '0'
                if field.get('name') == 'TS - Aprovador - EVT':
                    field['value'] = get_recipient_by_token(token) if tipo in ['aprovar', 'aprovar_selecionados'] else ''
                if field.get('name') == 'TS - Dt. Aprovação - EVT':
                    field['value'] = data_atual if tipo in ['aprovar', 'aprovar_selecionados'] else ''

            update_status, update_response = update_time_entry(entry_id, custom_fields)
            if update_status == 200 or 204:
                restaurar_data_original(entry_id, data_original)
                log_approval_rejection(entry_id, time_entry['spent_on'], time_entry['hours'], tipo, token)
                return {"message": f"Hora {'aprovada' if tipo in ['aprovar', 'aprovar_selecionados'] else 'reprovada'} para ID: {entry_id}"}
            else:
                restaurar_data_original(entry_id, data_original)
                return {"error": "Failed to update in Redmine", "details": update_response}
        else:
            if alterar_status not in [200, 204]:
                return {"error": "Failed to temporarily change date", "details": alterar_response}
            for field in custom_fields:
                if field.get('name') == 'TS - Aprovado - CLI':
                    field['value'] = '1' if tipo in ['aprovar', 'aprovar_selecionados'] else '0'
                if field.get('name') == 'TS - Dt. Aprovação - CLI':
                    field['value'] = data_atual if tipo in ['aprovar', 'aprovar_selecionados'] else ''
            update_status, update_response = update_time_entry(entry_id, custom_fields)
            if update_status == 200 or 204:
                restaurar_data_original(entry_id, data_original)
                log_approval_rejection(entry_id, time_entry['spent_on'], time_entry['hours'], tipo, token)
                return {"message": f"Hora {'aprovada' if tipo in ['aprovar', 'aprovar_selecionados'] else 'reprovada'} para ID: {entry_id}"}
            else:
                restaurar_data_original(entry_id, data_original)
                return {"error": "Failed to update in Redmine", "details": update_response}
    else:
        return {"error": "Failed to fetch time entry from Redmine", "details": response}


@app.route('/api/horas_nao_aprovadas', methods=['GET'])

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
#
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
    if user_id == '':
        user_id = recipient_email
    access_token = AccessToken(token=token, user_id=user_id, recipient_email=recipient_email)
    db.session.add(access_token)
    db.session.commit()
    return token


@app.route('/get_or_create_token', methods=['POST'])
def get_or_create_token_endpoint():
    try:
        data = request.json
        user_id = data.get('user_id', '')
        recipient_email = data['recipient_email']

        token = get_or_create_token(user_id, recipient_email)

        return jsonify({'token': token}), 200
    except Exception as e:
        logger.error(f"Erro ao obter ou criar token: {e}")
        return jsonify({'error': 'Erro ao obter ou criar token'}), 500


def get_email_from_token(token):
    # Tenta encontrar o token existente
    existing_token = AccessToken.query.filter_by(token=token).first()

    if existing_token:
        return existing_token.recipient_email

    return None


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
