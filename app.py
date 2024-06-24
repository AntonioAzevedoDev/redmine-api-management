import calendar
import json
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
                additional_message = f"\n\nAcesso ao painel de horas: <a href='{API_URL}relatorio_horas?page=1&token={token}'>Painel de Horas</a>"
                email_content += f"\n\n{additional_message}"

            send_email(email_content, email.strip(), project_name, user_name)
            logger.info(f"Enviando e-mail para: {email.strip()}")
        logger.info("E-mails enviados com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao enviar e-mails: {e}")


def send_email_task_client(file_content, recipient_email, project, user_id, user_name):
    logger.info("Tarefa de envio de e-mail (Cliente) iniciada.")
    try:
        logger.info("Chamando função send_email com o seguinte conteúdo para o cliente:")
        logger.info(file_content)
        token = get_or_create_token(user_id, recipient_email)
        link = f"{API_URL}relatorio_horas_client/{user_id}?token={token}&project={project['name']}"
        email_content = f"{file_content}\n\nPara visualizar as entradas de tempo, acesse o link: <a href='{link}'>relatório</a>"
        send_email(email_content, recipient_email.strip(), project['name'], user_name)
        logger.info(f"E-mail enviado para: {recipient_email.strip()}")
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
    try:
        user_id = request.headers.get('user_id', '')
        logger.info(f"Usuario {user_id} solicitando aprovação de horas.")
        project_identifier = request.headers.get('project')
        today = datetime.today()
        seven_days_ago = today - timedelta(days=7)
        start_date = seven_days_ago.strftime('%Y-%m-%d')
        end_date = today.strftime('%Y-%m-%d')

        project_id = None
        if project_identifier:
            project_url = f'{REDMINE_URL}/projects/{project_identifier}.json'
            project_response = requests.get(project_url, headers={
                'X-Redmine-API-Key': REDMINE_API_KEY,
                'Content-Type': 'application/json'
            }, verify=False)  # Consider replacing verify=False with a valid certificate

            if project_response.status_code == 200:
                project_data = project_response.json()
                project_id = project_data.get('project', {}).get('id')
            else:
                logger.error(f"Erro ao buscar o projeto: {project_response.status_code}")
                return jsonify('Erro ao buscar o projeto.'), 500

        url = f'{REDMINE_URL}/time_entries.json?user_id={user_id}&from={start_date}&to={end_date}'
        entries_response = requests.get(url, headers={
            'X-Redmine-API-Key': REDMINE_API_KEY,
            'Content-Type': 'application/json'
        }, verify=False)  # Consider replacing verify=False with a valid certificate

        if entries_response.ok:
            time_entries = entries_response.json().get('time_entries', [])

            # Filtrar entradas de tempo pelo ID do projeto
            if project_id:
                time_entries = [entry for entry in time_entries if entry.get('project', {}).get('id') == project_id]

            email_entries = defaultdict(list)

            for entry in time_entries:
                approver_field = next(
                    (f for f in entry.get('custom_fields', []) if f['name'] == 'TS - Aprovador - CLI' and f['value']),
                    None)
                if approver_field:
                    email_entries[approver_field['value']].append(entry)

            if not email_entries:
                logger.warning('Nenhuma entrada de tempo com o campo TS - Aprovador - CLI encontrada.')
                return jsonify('Nenhuma entrada de tempo com o campo TS - Aprovador - CLI encontrada.'), 400

            for email, entries in email_entries.items():

                unapproved_entries = [
                    entry for entry in entries if any(
                        field['name'] == 'TS - Aprovado - CLI' and (field['value'] == '0' or field['value'] == '')
                        for field in entry.get('custom_fields', [])
                    ) and any(
                        field['name'] == 'TS - Aprovado - EVT' and (field['value'] == '1' or field['value'] == '')
                        for field in entry.get('custom_fields', [])
                    )
                ]

                if unapproved_entries:
                    table_html = create_html_table_mail_client(unapproved_entries, email)
                    project = unapproved_entries[0]['project']
                    user_name = unapproved_entries[0]['user']['name']
                    send_email_task_client(table_html, email, project, user_id, user_name)
                else:
                    logger.info(f'Nenhuma entrada de tempo não aprovada encontrada para o email: {email}')

            return jsonify('Relatórios enviados com sucesso.'), 200
        else:
            logger.error('Erro ao buscar entradas de tempo.')
            return jsonify('Erro ao buscar entradas de tempo.'), 500
    except Exception as e:
        logger.error(f"Erro ao enviar relatórios por email: {e}")
        return jsonify("Erro ao enviar relatórios por email", 500)


@app.route('/send_email_report_client_geral', methods=['POST'])
def send_email_report_client_geral():
    try:
        data = request.get_json()
        time_entries_ids = [entry['id'] for entry in data['entries']]

        time_entries = []
        for entry_id in time_entries_ids:
            if entry_id != 'N/A':
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
            else:
                continue

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
            unapproved_entries = [
                entry for entry in entries if any(
                    field['name'] == 'TS - Aprovado - CLI' and (field['value'] == '0' or field['value'] == '')
                    for field in entry.get('custom_fields', [])
                ) and any(
                    field['name'] == 'TS - Aprovado - EVT' and (field['value'] == '1' or field['value'] == '')
                    for field in entry.get('custom_fields', [])
                )
            ]

            if unapproved_entries:
                table_html = create_html_table_mail_client(unapproved_entries, email)
                project = unapproved_entries[0]['project']
                user_name = unapproved_entries[0]['user']['name']
                user_id = unapproved_entries[0]['user']['id']
                send_email_task_client(table_html, email, project, user_id, user_name)
            else:
                logger.info(f'Nenhuma entrada de tempo não aprovada encontrada para o email: {email}')

        return jsonify({"message": "Relatórios enviados com sucesso."}), 200
    except Exception as e:
        logger.error(f"Erro ao enviar relatórios por email: {e}")
        return jsonify("Erro ao enviar relatórios por email", 500)


@app.route('/send_email_report', methods=['POST'])
def send_email_report():
    entry_id = request.headers.get('entryId', '')
    if not entry_id:
        return jsonify('ID de entrada não fornecido.'), 400
    status_code, response = get_time_entry(entry_id)
    time_entry = response.get('time_entry', {})
    user_id = time_entry['user']['id']
    logger.info(f"Usuario {user_id} solicitando aprovação de horas.")
    allowed_emails = request.headers.get('allowed_emails', '').split(',')
    today = datetime.today()
    seven_days_ago = today - timedelta(days=7)
    start_date = seven_days_ago.strftime('%Y-%m-%d')
    end_date = today.strftime('%Y-%m-%d')

    # url = f'{REDMINE_URL}/time_entries.json?user_id={user_id}&from={start_date}&to={end_date}'
    url = f'{REDMINE_URL}/time_entries.json?user_id={user_id}'
    entries_response = requests.get(url, headers={
        'X-Redmine-API-Key': REDMINE_API_KEY,
        'Content-Type': 'application/json'
    }, verify=False)

    if entries_response.ok:
        time_entries = entries_response.json().get('time_entries', [])
        unapproved_entries = [entry for entry in time_entries if any(
            field['name'] == 'TS - Aprovado - EVT' and (field['value'] == '0' or field['value'] == '') for field in
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
    total_horas = 0

    if is_client == '0':
        for entry_id in entry_ids:
            status_code, response = get_time_entry(entry_id)
            if status_code == 200:
                time_entry = response.get('time_entry', {})
                custom_fields = time_entry.get('custom_fields', [])

                data_original = time_entry.get('spent_on')
                nova_data = (datetime.now() + timedelta(days=4)).strftime('%Y-%m-%d')
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
                    total_horas += time_entry['hours']
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
            return {
                "error": "Some entries failed to update",
                "status": 207,
                "details": errors
            }

        return {
            "message": f"{total_horas} horas foram {'aprovadas' if aprovacao else 'reprovadas'} com sucesso!",
            "status": 200
        }
    else:
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
                    if field.get('name') == 'TS - Aprovado - CLI':
                        field['value'] = '1' if aprovacao else '0'
                    if field.get('name') == 'TS - Dt. Aprovação - CLI':
                        field['value'] = data_atual if aprovacao else ''

                update_status, update_response = update_time_entry(entry_id, custom_fields)
                if update_status in [200, 204]:
                    restaurar_data_original(entry_id, data_original)
                    log_approval_rejection(entry_id, time_entry['spent_on'], time_entry['hours'],
                                           'aprovar' if aprovacao else 'reprovar', token)
                    total_horas += time_entry['hours']
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
            return {
                "error": "Some entries failed to update",
                "status": 207,
                "details": errors
            }

        return {
            "message": f"{total_horas} horas foram {'aprovadas' if aprovacao else 'reprovadas'} com sucesso!",
            "status": 200
        }


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
            hora_final = next(
                (field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora final (HH:MM)'),
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
        project_name = request.args.get('project')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        is_client = 1 if 'client' in request.full_path else 0

        # Definir datas padrão (últimos 30 dias) se não fornecidas
        if not start_date or not end_date:
            today = datetime.today()
            first_day_of_month = today.replace(day=1)
            last_day_of_month = today.replace(day=calendar.monthrange(today.year, today.month)[1])
            start_date = first_day_of_month.strftime('%Y-%m-%d')
            end_date = last_day_of_month.strftime('%Y-%m-%d')

        # Construir URL de requisição com filtros
        url = f'{REDMINE_URL}/time_entries.json?user_id={user_id}&from={start_date}&to={end_date}'

        entries_response = requests.get(url, headers={
            'X-Redmine-API-Key': REDMINE_API_KEY,
            'Content-Type': 'application/json'
        }, verify=False)

        if entries_response.ok:
            # Filtra as entradas de tempo para incluir apenas aquelas que não foram aprovadas e têm o destinatário correto
            time_entries = entries_response.json().get('time_entries', [])
            unapproved_entries = [entry for entry in time_entries if any(
                field['name'] == 'TS - Aprovado - CLI' and (field['value'] == '0' or field['value'] == '') for field in
                entry.get('custom_fields', []))
                                  and any(
                field['name'] == 'TS - Aprovador - CLI' for field in entry.get('custom_fields', []))
                                  ]

            # Agrupar entradas por destinatário
            email_entries = defaultdict(list)
            for entry in time_entries:
                recipient = next(
                    (field['value'] for field in entry['custom_fields'] if field['name'] == 'TS - Aprovador - CLI'),
                    None)
                if recipient:
                    email_entries[recipient].append(entry)

            if not time_entries:
                logger.warning(
                    f"Nenhuma entrada de tempo não aprovada encontrada para o usuário ID {user_id} no período de {start_date} a {end_date}")
                return render_response("Nenhuma entrada de tempo encontrada", 404)

            token = request.args.get('token')
            token_email = get_email_from_token(token)  # Obtendo o e-mail associado ao token
            logger.warning(f'TOKEN_EMAIL:{token_email}')

            for recipient, entries in email_entries.items():
                # Validação do e-mail do token com o recipient
                if token_email != recipient:
                    logger.warning(f'Token não autorizado para o e-mail: {recipient} ')
                    continue

                table_html = create_html_table_client(entries, recipient)
                # Constrói a lista de IDs das entradas
                approve_entry_ids = ','.join(
                    [str(entry['id']) for entry in unapproved_entries if
                     any(field['name'] == 'TS - Aprovado - CLI' and (field['value'] == '0' or field['value'] == '') for
                         field in entry.get('custom_fields', []))]
                )
                reject_entry_ids = ','.join(
                    [str(entry['id']) for entry in unapproved_entries if
                     any(field['name'] == 'TS - Aprovado - CLI' and (field['value'] == '1' or field['value'] == '') for
                         field in entry.get('custom_fields', []))]
                )
                approved = any(
                    field['name'] == 'TS - Aprovado - CLI' and field['value'] == '1' for field in entry['custom_fields']
                )

                repproved = any(
                    field['name'] == 'TS - Aprovado - CLI' and field['value'] == '0' for field in entry['custom_fields']
                )

                unnaproved = any(
                    field['name'] == 'TS - Aprovado - CLI' and field['value'] == '' for field in entry['custom_fields']
                )
                # Extrai usuários e projetos para os filtros
                usuarios = {entry['user']['name'] for entry in time_entries}
                projetos = {entry['project']['name'] for entry in time_entries}

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
                            var isCollapsed = fieldset.classList.toggle('collapsed');
                            var div = fieldset.querySelector('div');
                            var arrow = legend.querySelector('.arrow');
                            if (isCollapsed) {{
                                div.style.display = 'none';
                                arrow.innerHTML = '▼';  // Seta para a direita
                            }} else {{
                                div.style.display = 'block';
                                arrow.innerHTML = '▶';  // Seta para baixo
                            }}
                        }}

                        document.addEventListener('DOMContentLoaded', function() {{
                            // Lógica de seleção automática de projetos e filtros
                            
                            const projectSelect = document.getElementById('projectSelect');
                            const project_name = "{project_name}";
                            if (projectSelect && project_name) {{
                                const options = projectSelect.options;
                                for (let i = 0; i < options.length; i++) {{
                                    if (options[i].text.toUpperCase() === project_name.toUpperCase()) {{
                                        projectSelect.selectedIndex = i;
                                        filterBySelect();
                                        break;
                                    }}
                                }}
                            }}

                            document.getElementById("filterInput").addEventListener("keyup", function() {{
                                filterBySelect();
                            }});

                            document.getElementById("userSelect").addEventListener("change", function() {{
                                filterBySelect();
                            }});

                            document.getElementById("projectSelect").addEventListener("change", function() {{
                                filterBySelect();
                            }});

                            document.getElementById("approvalSelect").addEventListener("change", function() {{
                                filterBySelect();
                            }});

                            const tableRows = document.querySelectorAll('#time_entries_table tbody tr');

                            tableRows.forEach(row => {{
                                row.addEventListener('click', function() {{
                                 if (window.innerWidth <= 768) {{
                                    var entryData = {{
                                        spent_on: row.cells[1].textContent.trim(),
                                        user: {{ name: row.cells[2].textContent.trim() }},
                                        activity: {{ name: row.cells[3].textContent.trim() }},
                                        project: {{ name: row.cells[4].textContent.trim() }},
                                        comments: row.cells[5].textContent.trim(),
                                        custom_fields: [
                                            {{ name: 'Hora inicial (HH:MM)', value: row.cells[6].textContent.trim() }},
                                            {{ name: 'Hora final (HH:MM)', value: row.cells[7].textContent.trim() }},
                                            {{ name: 'Local de trabalho', value: 'Indisponível' }},
                                            {{ name: 'TS - Aprovado - CLI', value: row.cells[9].textContent.trim() }}
                                        ],
                                        hours: row.cells[8].textContent.trim(),
                                        id: row.id.split('-')[2]
                                    }};
                                    if (entryData) {{
                                        var entry = entryData;

                                        var popup = document.getElementById('detailsPopup');
                                        var content = document.getElementById('popupContent');

                                        var horaInicial = entry.custom_fields.find(field => field.name === 'Hora inicial (HH:MM)').value;
                                        var horaFinal = entry.custom_fields.find(field => field.name === 'Hora final (HH:MM)').value;
                                        var localTrabalho = entry.custom_fields.find(field => field.name === 'Local de trabalho').value;
                                        var aprovado = entry.custom_fields.find(field => field.name === 'TS - Aprovado - CLI').value;
                                        var approved_value = (aprovado === '1') ? 'Sim' : (aprovado === '0') ? 'Não' : 'Pendente';

                                        content.innerHTML = `
                                            <p><strong>Data:</strong> ${{entry['spent_on']}}</p>
                                            <p><strong>Usuário:</strong> ${{entry['user']['name']}}</p>
                                            <p><strong>Atividade:</strong> ${{entry['activity']['name']}}</p>
                                            <p><strong>Projeto:</strong> ${{entry['project']['name']}}</p>
                                            <p><strong>Comentários:</strong> ${{entry['comments']}}</p>
                                            <p><strong>Hora Inicial:</strong> ${{horaInicial}}</p>
                                            <p><strong>Hora Final:</strong> ${{horaFinal}}</p>
                                            <p><strong>Total de Horas:</strong> ${{entry['hours']}}</p>
                                            <p><strong>Aprovado:</strong> ${{aprovado}}</p>
                                            <div class="btn-group">
                                                <a href="#" onclick="approveHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{aprovado}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-approve-table ${{aprovado === 'Sim' ? 'disabled' : ''}}" style="opacity:${{aprovado === 'Sim' ? '0' : '1'}};">Aprovar</a>
                                                <a href="#" onclick="rejectHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{aprovado}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-reject-table ${{aprovado === 'Sim' ? 'disabled' : ''}}" style="opacity:${{aprovado === 'Sim' ? '0' : '1'}};">Reprovar</a>
                                            </div>
                                        `;
                                        popup.style.display = 'block';
                                    }} else {{
                                        console.error('Dados da entrada não encontrados.');
                                    }}
                                    }}
                                }});
                            }});
                        }});

                        function filterTable() {{
                            filterBySelect();
                        }}

                        function filterBySelect() {{
                            var userSelect = document.getElementById("userSelect").value.toUpperCase();
                            var projectSelect = document.getElementById("projectSelect").value.toUpperCase();
                            var approvalSelect = document.getElementById("approvalSelect").value.toUpperCase();
                            var table = document.getElementById("time_entries_table");
                            var tr = table.getElementsByTagName("tr");

                            let totalHours = 0;
                            let approvedHours = 0;
                            let repprovedHours = 0;
                            let unapprovedHours = 0;

                            let filteredApproveIds = [];
                            let filteredRejectIds = [];

                            for (var i = 1; i < tr.length; i++) {{
                                tr[i].style.display = "none";
                                var userTd = tr[i].getElementsByTagName("td")[2];
                                var projectTd = tr[i].getElementsByTagName("td")[4];
                                var approvalTd = tr[i].getElementsByTagName("td")[9];
                                if (userTd && projectTd && approvalTd) {{
                                    var userValue = userTd.textContent || userTd.innerText;
                                    var projectValue = projectTd.textContent || projectTd.innerText;
                                    var approvalValue = approvalTd.textContent || approvalTd.innerText;
                                    if ((userSelect === "ALL" || userValue.toUpperCase() === userSelect) &&
                                        (projectSelect === "ALL" || projectValue.toUpperCase() === projectSelect) &&
                                        (approvalSelect === "ALL" || approvalValue.toUpperCase() === approvalSelect)) {{
                                        tr[i].style.display = "";
                                        var entryId = tr[i].getElementsByTagName("td")[0].querySelector("input").value;
                                        var entryHours = parseFloat(tr[i].getElementsByTagName("td")[8].textContent);
                                        totalHours += entryHours;
                                        if (approvalValue === 'Sim') {{
                                            approvedHours += entryHours;

                                        }} else if (approvalValue === 'Não') {{
                                            repprovedHours += entryHours;
                                            filteredApproveIds.push(entryId);

                                        }} else if (approvalValue === 'Pendente') {{
                                            unapprovedHours += entryHours;
                                            filteredApproveIds.push(entryId);
                                            filteredRejectIds.push(entryId);
                                        }}
                                    }}
                                }}
                            }}

                            document.querySelector('.hours-total').textContent = totalHours.toFixed(1);
                            document.querySelector('.hours-approved').textContent = approvedHours.toFixed(1);
                            document.querySelector('.hours-repproved').textContent = repprovedHours.toFixed(1);
                            document.querySelector('.hours-unapproved').textContent = unapprovedHours.toFixed(1);

                            // Atualiza os botões no modo desktop
                            document.querySelector('.btn-approve').setAttribute('onclick', `approveAll('{token}', '${{filteredApproveIds.join(',')}}', {is_client})`);
                            document.querySelector('.btn-reject').setAttribute('onclick', `rejectAll('{token}', '${{filteredRejectIds.join(',')}}', {is_client})`);

                            // Atualiza os botões no modo mobile
                            document.querySelector('.mobile-actions .btn-approve').setAttribute('onclick', `approveAll('{token}', '${{filteredApproveIds.join(',')}}', {is_client})`);
                            document.querySelector('.mobile-actions .btn-reject').setAttribute('onclick', `rejectAll('{token}', '${{filteredRejectIds.join(',')}}', {is_client})`);

                            // Update mobile summary
                            updateMobileSummary();
                        }}

                        function toggleAll(source) {{
                            checkboxes = document.getElementsByName('selected_entries');
                            for(var i=0, n=checkboxes.length;i<n;i++) {{
                                if (!checkboxes[i].disabled) {{
                                    checkboxes[i].checked = source.checked;
                                }}
                            }}
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
                                showAlert('Relatório enviado com sucesso', 'success');
                            }})
                            .catch((error) => {{
                                showAlert('Erro ao enviar o relatório: ' + error, 'error');
                            }});
                        }}

                        function showAlert(message, type) {{
                            var alertDiv = document.createElement('div');
                            alertDiv.className = `alert alert-${type}`;
                            alertDiv.textContent = message;

                            // Estilização básica para o popup
                            alertDiv.style.position = 'fixed';
                            alertDiv.style.top = '20px';
                            alertDiv.style.left = '50%';
                            alertDiv.style.transform = 'translateX(-50%)';
                            alertDiv.style.padding = '10px';
                            alertDiv.style.zIndex = 1000;
                            alertDiv.style.backgroundColor = type === 'success' ? 'green' : 'red';
                            alertDiv.style.color = 'white';
                            alertDiv.style.borderRadius = '5px';
                            alertDiv.style.boxShadow = '0 0 10px rgba(0, 0, 0, 0.1)';
                            alertDiv.style.fontSize = '16px';

                            document.body.appendChild(alertDiv);

                            // Remover o popup após 3 segundos
                            setTimeout(() => {{
                                document.body.removeChild(alertDiv);
                            }}, 3000);
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
                                        id: td[0] && td[0].querySelector("input") ? td[0].querySelector("input").value : "N/A",
                                        date: td[1] ? td[1].textContent : "N/A",
                                        user: td[2] ? td[2].textContent : "N/A",
                                        activity: td[3] ? td[3].textContent : "N/A",
                                        project: td[4] ? td[4].textContent : "N/A",
                                        comments: td[5] ? td[5].textContent : "N/A",
                                        start_time: td[6] ? td[6].textContent : "N/A",
                                        end_time: td[7] ? td[7].textContent : "N/A",
                                        hours: td[8] ? td[8].textContent : "N/A"
                                    }};

                                    data.push(entry);
                                }}
                            }} else {{
                                for (var i = 1; i < tr.length; i++) {{
                                    if (tr[i].style.display !== "none") {{
                                        var td = tr[i].getElementsByTagName("td");

                                        var entry = {{
                                            id: td[0] && td[0].querySelector("input") ? td[0].querySelector("input").value : "N/A",
                                            date: td[1] ? td[1].textContent : "N/A",
                                            user: td[2] ? td[2].textContent : "N/A",
                                            activity: td[3] ? td[3].textContent : "N/A",
                                            project: td[4] ? td[4].textContent : "N/A",
                                            comments: td[5] ? td[5].textContent : "N/A",
                                            start_time: td[6] ? td[6].textContent : "N/A",
                                            end_time: td[7] ? td[7].textContent : "N/A",
                                            hours: td[8] ? td[8].textContent : "N/A"
                                        }};

                                        data.push(entry);
                                    }}
                                }}
                            }}

                            return data;
                        }}

                        function approveAll(token, entryIds, isClient) {{
                            fetch("{API_URL}aprovar_todos?token=" + token + "&entries=" + entryIds + "&client=" + isClient)
                            .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
                            .then(result => {{
                                const status = result.status;
                                const body = result.body;
                                showAlert(body.message, status === 200 ? 'success' : 'error');
                                if (status === 200) {{
                                    location.reload();
                                }}
                            }})
                            .catch(error => {{
                                console.error('Erro:', error);
                                showAlert('Erro ao aprovar horas.', 'error');
                            }});
                        }}

                        function rejectAll(token, entryIds, isClient) {{
                            fetch("{API_URL}reprovar_todos?token=" + token + "&entries=" + entryIds + "&client=" + isClient)
                            .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
                            .then(result => {{
                                const status = result.status;
                                const body = result.body;
                                showAlert(body.message, status === 200 ? 'success' : 'error');
                                if (status === 200) {{
                                    location.reload();
                                }}
                            }})
                            .catch(error => {{
                                console.error('Erro:', error);
                                showAlert('Erro ao reprovar horas.', 'error');
                            }});
                        }}

                        function updateRowsApproval(entryIds, isApproved) {{
                            var table = document.getElementById("time_entries_table");
                            var tr = table.getElementsByTagName("tr");

                            let totalHours = 0;
                            let approvedHours = 0;
                            let repprovedHours = 0;
                            let pendingHours = 0;

                            for (var i = 1; i < tr.length; i++) {{
                                var row = tr[i];
                                var entryId = row.getElementsByTagName("td")[0].querySelector("input").value;
                                var td = row.getElementsByTagName("td");
                                var entryHours = parseFloat(td[8].textContent);
                                var approvalValue = td[9].textContent;

                                if (entryIds.includes(entryId)) {{
                                    if (isApproved && approvalValue !== "Sim") {{
                                        td[9].textContent = "Sim";
                                        approvedHours += entryHours;
                                        if (approvalValue === "Não") {{
                                            repprovedHours -= entryHours;
                                        }} else if (approvalValue === "Pendente") {{
                                            pendingHours -= entryHours;
                                        }}
                                    }} else if (!isApproved && approvalValue !== "Não") {{
                                        td[9].textContent = "Não";
                                        repprovedHours += entryHours;
                                        if (approvalValue === "Sim") {{
                                            approvedHours -= entryHours;
                                        }} else if (approvalValue === "Pendente") {{
                                            pendingHours -= entryHours;
                                        }}
                                    }}
                                    disableRow(entryId);
                                }} else {{
                                    if (approvalValue === "Sim") {{
                                        approvedHours += entryHours;
                                    }} else if (approvalValue === "Não") {{
                                        repprovedHours += entryHours;
                                    }} else if (approvalValue === "Pendente") {{
                                        pendingHours += entryHours;
                                    }}
                                }}
                                totalHours += entryHours;
                            }}

                            document.querySelector('.hours-total').textContent = totalHours.toFixed(1);
                            document.querySelector('.hours-approved').textContent = approvedHours.toFixed(1);
                            document.querySelector('.hours-repproved').textContent = repprovedHours.toFixed(1);
                            document.querySelector('.hours-unapproved').textContent = pendingHours.toFixed(1);

                            // Update mobile summary
                            updateMobileSummary();
                        }}

                        function disableRow(entryId) {{
                            var row = document.getElementById("entry-row-" + entryId);
                            var checkBox = row.querySelector('input[type="checkbox"]');
                            var approveButton = row.querySelector('.btn-approve-table');
                            var rejectButton = row.querySelector('.btn-reject-table');

                            if (checkBox) {{
                                checkBox.disabled = true;
                            }}
                            if (approveButton) {{
                                approveButton.classList.add('disabled');
                            }}
                            if (rejectButton) {{
                                rejectButton.classList.add('disabled');
                            }}
                        }}

                        function showDetailsPopup(entry) {{
                            var popup = document.getElementById('detailsPopup');
                            var content = document.getElementById('popupContent');
                            var horaInicial = entry.custom_fields.find(field => field.name === 'Hora inicial (HH:MM)').value;
                            var horaFinal = entry.custom_fields.find(field => field.name === 'Hora final (HH:MM)').value;
                            var localTrabalho = entry.custom_fields.find(field => field.name === 'Local de trabalho').value;
                            var aprovado = entry.custom_fields.find(field => field.name === 'TS - Aprovado - CLI').value;
                            var approved_value = (aprovado === 'Sim') ? 'Sim' : (aprovado === 'Não') ? 'Não' : 'Pendente';

                            content.innerHTML = `
                                <p><strong>Data:</strong> ${{entry['spent_on']}}</p>
                                <p><strong>Usuário:</strong> ${{entry['user']['name']}}</p>
                                <p><strong>Atividade:</strong> ${{entry['activity']['name']}}</p>
                                <p><strong>Projeto:</strong> ${{entry['project']['name']}}</p>
                                <p><strong>Comentários:</strong> ${{entry['comments']}}</p>
                                <p><strong>Hora Inicial:</strong> ${{horaInicial}}</p>
                                <p><strong>Hora Final:</strong> ${{horaFinal}}</p>
                                <p><strong>Total de Horas:</strong> ${{entry['hours']}}</p>
                                <p><strong>Aprovado:</strong> ${{approved_value}}</p>
                                <div class="btn-group">
                                    <a href="#" onclick="approveHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-approve-table ${{approved_value === 'Sim' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Sim' ? '0' : '1'}};">Aprovar</a>
                                    <a href="#" onclick="rejectHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-reject-table ${{approved_value === 'Não' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Não' ? '0' : '1'}};">Reprovar</a>
                                </div>
                            `;
                            popup.style.display = 'block';
                        }}

                        function hideDetailsPopup() {{
                            var popup = document.getElementById('detailsPopup');
                            popup.style.display = 'none';
                        }}

                        function updateMobileSummary() {{
                            document.querySelector('.hours-total-mobile').textContent = document.querySelector('.hours-total').textContent;
                            document.querySelector('.hours-approved-mobile').textContent = document.querySelector('.hours-approved').textContent;
                            document.querySelector('.hours-repproved-mobile').textContent = document.querySelector('.hours-repproved').textContent;
                            document.querySelector('.hours-unapproved-mobile').textContent = document.querySelector('.hours-unapproved').textContent;
                        }}

                        // Ensure initial values are set for mobile view
                        document.addEventListener('DOMContentLoaded', function() {{
                            updateMobileSummary();
                            if (window.innerWidth <= 768) {{ // Verifica se a largura da janela é de 768px ou menos (modo mobile)
                                var thHoraInicial = document.querySelector('#time_entries_table thead tr th:nth-child(7)');
                                if (thHoraInicial) {{
                                    thHoraInicial.textContent = 'Hora Inicial';
                                }}
                            
                                var thHoraFinal = document.querySelector('#time_entries_table thead tr th:nth-child(8)');
                                if (thHoraFinal) {{
                                    thHoraFinal.textContent = 'Hora Final';
                                }}
                                var thTotalHoras = document.querySelector('#time_entries_table thead tr th:nth-child(9)');
                                if (thTotalHoras) {{
                                    thTotalHoras.textContent = 'Total Horas';
                                }}
                                var columnsToHide = [4, 5, 6, 11]; // Índices das colunas a serem escondidas
                                columnsToHide.forEach(function(index) {{
                                    var thXPath = `//*[@id="time_entries_table"]/thead/tr/th[${{index}}]`;
                                    var th = document.evaluate(thXPath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                                    if (th) th.style.display = 'none';
                    
                                    var tdXPath = `//*[@id="time_entries_table"]/tbody/tr/td[${{index}}]`;
                                    var tds = document.evaluate(tdXPath, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
                                    for (var i = 0; i < tds.snapshotLength; i++) {{
                                        tds.snapshotItem(i).style.display = 'none';
                                    }}
                                }});
                            }}
                        }});
                    </script>
                    <style>
                        body {{
                            overflow-y: auto; /* Adiciona a barra de rolagem vertical ao body */
                            margin: 0;
                            padding: 0;
                        }}
                        #header {{
                            position: fixed;
                            top: 0;
                            width: 100%;
                            z-index: 10; /* Garante que o header fique sobre outros elementos */
                            background-color: #333333; /* Defina a cor de fundo original aqui */
                            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1); /* Adicione uma sombra para o header */
                        }}
                        .container {{
                            display: flex;
                            flex-direction: column;
                            margin-top: 60px; /* Espaço para o header fixo */
                        }}
                        .table-container th:nth-child(11), .table-container td:nth-child(11) {{
                            width: 100px; /* Define uma largura menor para a coluna "Ações" */
                            text-align: center; /* Centraliza o texto e os botões na coluna */
                        }}
                        .filters-container {{
                            display: flex;
                            flex-direction: column;
                            align-items: stretch;
                            width: 100%;
                        }}

                        .toggle-filters {{
                            background-color: #1E90FF;
                            color: white;
                            padding: 10px;
                            text-align: center;
                            border: none;
                            border-radius: 5px;
                            margin-bottom: 10px;
                            width: 100%;
                            max-width: 200px;
                            align-self: center;
                        }}

                        #time_entries_form {{
                            display: flex;
                            flex-direction: column;
                            gap: 10px;
                            width: 100%;
                        }}

                        #filter-fields {{
                            display: flex;
                            flex-direction: column;
                            gap: 10px;
                        }}

                        .filters label {{
                            font-weight: bold;
                            margin-bottom: 5px;
                        }}

                        .filters input, .filters select {{
                            width: 100%;
                            padding: 10px;
                            border: 1px solid #ddd;
                            border-radius: 5px;
                        }}

                        .legend-text {{
                            display: none; /* Oculta a legenda no modo mobile */
                        }}

                        .arrow {{
                            display: none; /* Oculta a seta no modo mobile */
                        }}
                        .table-container {{
                            width: 100%;
                            max-height: 450px; /* Define uma altura máxima para a tabela */
                        }}
                        .table-container th:nth-child(11), .table-container td:nth-child(11) {{
                            width: 120px; /* Define uma largura menor para a coluna "Ações" */
                            text-align: center; /* Centraliza o texto e os botões na coluna */
                        }}
                        .table-container td {{
                            padding: 4px; /* Diminui a altura dos td */
                            text-align: left;
                            border-bottom: 1px solid #ddd;
                            vertical-align: middle; /* Garante que o conteúdo fique alinhado verticalmente */
                            white-space: nowrap; /* Impede quebra de linha em células */
                            overflow: hidden; /* Oculta conteúdo que ultrapassa o limite */
                            text-overflow: ellipsis; /* Adiciona reticências ao conteúdo excedente */
                        }}
                        .table-container th {{
                            background-color: #f2f2f2;
                            position: sticky;
                            top: 0;
                            z-index: 1;
                            text-align: center; /* Centraliza o texto do thead */
                        }}
                        .table-container {{
                            font-size: 0.9em;
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
                        .btn-group {{
                            display: flex;
                            justify-content: center;
                            margin-top: 20px;
                        }}
                        .btn-approve-table, .btn-reject-table {{
                            display: inline-block;
                            width: 90px;
                            margin-right: 5px; /* Adiciona espaçamento entre os botões */
                            text-align: center; /* Centraliza o texto do botão */
                        }}
                        .btn-approve-table {{
                            background-color: #28a745;
                            color: white;
                            margin-bottom: 5px; /* Adiciona espaçamento vertical entre os botões */
                        }}
                        .btn-reject-table {{
                            background-color: #dc3545;
                            color: white;
                            margin-top: 5px;
                        }}
                        .btn-approve-table.disabled, .btn-reject-table.disabled {{
                            visibility: hidden; /* Torna os botões invisíveis quando desabilitados */
                        }}
                        .btn-relatorio:hover {{
                            background-color: #63B8FF; /* Azul claro ao passar o mouse */
                        }}
                        @media (max-width: 768px) {{
                            .filters-container {{
                                display: flex;
                                flex-direction: column;
                                align-items: stretch;
                                width: 100%;
                            }}
                            .toggle-filters {{
                                background-color: #1E90FF;
                                color: white;
                                padding: 10px;
                                text-align: center;
                                border: none;
                                border-radius: 5px;
                                margin: 10px 0;
                                width: 80%;
                                max-width: 130px;
                                align-self: center;
                            }}
                            #time_entries_form {{
                                display: flex;
                                flex-direction: column;
                                gap: 10px;
                                width: 100%;
                            }}
                            #filter-fields {{
                                display: flex;
                                flex-direction: column;
                                gap: 10px;
                            }}
                            .filters label {{
                                font-weight: bold;
                                margin-bottom: 5px;
                            }}
                            .filters input, .filters select {{
                                width: 100%;
                                padding: 10px;
                                border: 1px solid #ddd;
                                border-radius: 5px;
                            }}
                            .legend-text {{
                                display: none; /* Oculta a legenda no modo mobile */
                            }}
                            .arrow {{
                                display: none; /* Oculta a seta no modo mobile */
                            }}
                            .container {{
                                padding: 10px;
                                overflow-y: auto;
                                max-height: 80vh;
                            }}
                            .header-logo h1 {{
                                font-size: 1.5em;
                            }}
                            .filters {{
                                display: flex;
                                align-items: center;
                                gap: 10px;
                                margin: 0; /* Remove margem */
                                padding: 0; /* Remove padding */
                            }}
                            .table-wrapper {{
                                overflow-x: auto;
                            }}
                            .table-container {{
                                font-size: 0.9em;
                                overflow-x: scroll;
                            }}
                            .btn-group {{
                                flex-direction: column;
                                align-items: center;
                            }}
                            .btn-group .btn-relatorio {{
                                width: 180px; /* Ocupa a largura total do contêiner no modo mobile */
                                height: 40px; /* Garante que a altura do botão seja mantida */
                                margin: 0px 0;
                            }}
                            #hours-summary {{
                                display: block; /* Mostrar no modo mobile */
                            }}
                        }}
                        @media (min-width: 769px) {{
                            .toggle-filters {{
                                display: none;
                            }}
                            #time_entries_form {{
                                display: block !important;
                            }}
                            #hours-summary {{
                                display: none; /* Esconder no modo desktop */
                            }}
                            .legend-text {{
                                display: block; /* Mostrar a legenda no modo desktop */
                            }}
                            .arrow {{
                                display: inline; /* Mostrar a seta no modo desktop */
                            }}
                        }}
                        .filters label, .legend-button {{
                            color: black;
                        }}
                        table {{
                            width: 100%;
                        }}
                        #detailsPopup {{
                            display: none;
                            position: fixed;
                            top: 50%;
                            left: 50%;
                            transform: translate(-50%, -50%);
                            background-color: white;
                            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3);
                            z-index: 1000;
                            padding: 20px;
                            border-radius: 5px;
                            max-width: 90%;
                            max-height: 90%;
                            overflow-y: auto;
                        }}
                        #detailsPopup .btn-group {{
                            display: flex;
                            justify-content: space-between;
                            margin-top: 20px;
                        }}
                        .close-button {{
                            position: absolute;
                            top: 10px;
                            right: 10px;
                            background: none;
                            border: none;
                            font-size: 1.5rem;
                            cursor: pointer;
                        }}
                        .close-button:hover {{
                            color: red;
                        }}
                        @media (max-width: 768px) {{
                            #all-actions {{
                                display: none;
                            }}
                            #hours-summary-table {{
                                display: none;
                            }}
                            .mobile-actions {{
                                display: block;
                            }}
                            #hours-summary {{
                                display: block;
                            }}
                            .hours-summary {{
                                font-size: 1.2em;
                                font-weight: bold;
                                color: #333;
                                margin-top: 10px;
                            }}
                            .hours-summary p {{
                                margin: 5px 0;
                            }}
                            .hours-total-mobile, .hours-approved-mobile, .hours-unapproved-mobile {{
                                color: #1E90FF;
                            }}
                            .hours-approved-mobile {{
                                color: #28a745;
                            }}
                            .hours-repproved-mobile {{
                                color: #dc3545;
                            }}
                            .hours-unapproved-mobile {{
                                color: #bbdb03;
                            }}
                        }}
                        @media (min-width: 769px) {{
                            #mobile-actions-buttons {{
                                display: none; /* Tornar invisível no modo desktop */
                            }}
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
                        <div id="hours-summary" class="hours-summary">
                            <p>Total de Horas: <span class="hours-total-mobile">0</span></p>
                            <p>Horas Aprovadas: <span class="hours-approved-mobile">0</span></p>
                            <p>Horas Reprovadas: <span class="hours-repproved-mobile">0</span></p>
                            <p>Horas Pendentes: <span class="hours-unapproved-mobile">0</span></p>
                        </div>
                        <div id="mobile-actions-buttons" class="mobile-actions">
                            <div class="btn-group">
                                <button type="button" onclick="approveAll('{token}', '{approve_entry_ids}', {is_client})" class="btn btn-approve">Aprovar Todos</button>
                                <button type="button" onclick="rejectAll('{token}', '{reject_entry_ids}', {is_client})" class="btn btn-reject">Reprovar Todos</button>
                            </div>
                        </div>
                        <div class="filters-container">
                            <button class="toggle-filters" onclick="toggleFilters()">Filtros</button>
                            <form id="time_entries_form" method="get" action="https://timesheetqas.evtit.com/validar_selecionados?client={is_client}">
                                <fieldset class="collapsible" style="border: none;">
                                    <legend class="legend-text" onclick="toggleFieldset(this);">
                                        <span class="legend-button">
                                            <span class="arrow">▶</span>
                                            Filtros
                                        </span>
                                    </legend>
                                    <div id="filter-fields" class="filter-fields-style" style="display: block;">
                                        <label for="filterInput">Buscar:</label>
                                        <input type="text" id="filterInput" onkeyup="filterBySelect()" placeholder="Digite para buscar...">
                                        <label for="userSelect">Usuário:</label>
                                        <select id="userSelect" onchange="filterBySelect()">
                                            <option value="ALL">Todos</option>
                                            {''.join(
                    [f'<option value="{usuario.upper()}">{usuario}</option>' for usuario in sorted(usuarios)])}
                                        </select>
                                        <label for="projectSelect">Projeto:</label>
                                        <select id="projectSelect" onchange="filterBySelect()">
                                            <option value="ALL">Todos</option>
                                            {''.join(
                    [f'<option value="{projeto.upper()}">{projeto}</option>' for projeto in sorted(projetos)])}
                                        </select>
                                        <label for="approvalSelect">Aprovado:</label>
                                        <select id="approvalSelect" onchange="filterBySelect()">
                                            <option value="ALL">Todos</option>
                                            <option value="SIM">Aprovadas</option>
                                            <option value="NÃO">Reprovadas</option>
                                            <option value="PENDENTE">Pendentes</option>
                                        </select>
                                    </div>
                                </fieldset>
                            </form>
                        </div>
                        <div class="table-container">
                            {table_html}
                            <div id="all-actions" class="btn-group">
                                <button type="button" onclick="approveAll('{token}', '{approve_entry_ids}', {is_client})" class="btn btn-approve">Aprovar Todos</button>
                                <button type="button" onclick="rejectAll('{token}', '{reject_entry_ids}', {is_client})" class="btn btn-reject">Reprovar Todos</button>
                            </div>
                            <div id="selected-actions" class="btn-group">
                                <button type="button" id="approve-selected" class="btn btn-approve" data-action="aprovar">Aprovar Selecionados</button>
                                <button type="button" id="reject-selected" class="btn btn-reject" data-action="reprovar">Reprovar Selecionados</button>

                            </div>
                        </div>
                    </div>
                    <div id="detailsPopup">
                        <div id="popupContent"></div>
                        <button type="button" class="close-button" onclick="hideDetailsPopup()">×</button>
                    </div>
                    <script>
                        document.addEventListener('DOMContentLoaded', function() {{
                            const projectSelect = document.getElementById('projectSelect');
                            if (projectSelect && project_name) {{
                                const options = projectSelect.options;
                                for (let i = 0; i < options.length; i++) {{
                                    if (options[i].text === project_name) {{
                                        projectSelect.selectedIndex = i;
                                        break;
                                    }}
                                }}
                            }}

                            document.getElementById("filterInput").addEventListener("keyup", function() {{
                                filterBySelect();
                            }});

                            document.getElementById("userSelect").addEventListener("change", function() {{
                                filterBySelect();
                            }});

                            document.getElementById("projectSelect").addEventListener("change", function() {{
                                filterBySelect();
                            }});

                            document.getElementById("approvalSelect").addEventListener("change", function() {{
                                filterBySelect();
                            }});

                            const tableRows = document.querySelectorAll('#time_entries_table tbody tr');

                            tableRows.forEach(row => {{
                                row.addEventListener('click', function() {{
                                 if (window.innerWidth <= 768) {{
                                    var entryData = {{
                                        spent_on: row.cells[1].textContent.trim(),
                                        user: {{ name: row.cells[2].textContent.trim() }},
                                        activity: {{ name: row.cells[3].textContent.trim() }},
                                        project: {{ name: row.cells[4].textContent.trim() }},
                                        comments: row.cells[5].textContent.trim(),
                                        custom_fields: [
                                            {{ name: 'Hora inicial (HH:MM)', value: row.cells[6].textContent.trim() }},
                                            {{ name: 'Hora final (HH:MM)', value: row.cells[7].textContent.trim() }},
                                            {{ name: 'Local de trabalho', value: 'Indisponível' }},
                                            {{ name: 'TS - Aprovado - CLI', value: row.cells[9].textContent.trim() }}
                                        ],
                                        hours: row.cells[8].textContent.trim(),
                                        id: row.id.split('-')[2]
                                    }};
                                    if (entryData) {{
                                        var entry = entryData;

                                        var popup = document.getElementById('detailsPopup');
                                        var content = document.getElementById('popupContent');

                                        var horaInicial = entry.custom_fields.find(field => field.name === 'Hora inicial (HH:MM)').value;
                                        var horaFinal = entry.custom_fields.find(field => field.name === 'Hora final (HH:MM)').value;
                                        var localTrabalho = entry.custom_fields.find(field => field.name === 'Local de trabalho').value;
                                        var aprovado = entry.custom_fields.find(field => field.name === 'TS - Aprovado - CLI').value;
                                        var approved_value = (aprovado === '1') ? 'Sim' : (aprovado === '0') ? 'Não' : 'Pendente';

                                        content.innerHTML = `
                                            <p><strong>Data:</strong> ${{entry['spent_on']}}</p>
                                            <p><strong>Usuário:</strong> ${{entry['user']['name']}}</p>
                                            <p><strong>Atividade:</strong> ${{entry['activity']['name']}}</p>
                                            <p><strong>Projeto:</strong> ${{entry['project']['name']}}</p>
                                            <p><strong>Comentários:</strong> ${{entry['comments']}}</p>
                                            <p><strong>Hora Inicial:</strong> ${{horaInicial}}</p>
                                            <p><strong>Hora Final:</strong> ${{horaFinal}}</p>
                                            <p><strong>Total de Horas:</strong> ${{entry['hours']}}</p>
                                            <p><strong>Aprovado:</strong> ${{aprovado}}</p>
                                            <div class="btn-group">
                                                <a href="#" onclick="approveHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{aprovado}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-approve-table ${{aprovado === 'Sim' ? 'disabled' : ''}}" style="opacity:${{aprovado === 'Sim' ? '0' : '1'}};">Aprovar</a>
                                                <a href="#" onclick="rejectHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{aprovado}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-reject-table ${{aprovado === 'Sim' ? 'disabled' : ''}}" style="opacity:${{aprovado === 'Sim' ? '0' : '1'}};">Reprovar</a>
                                            </div>
                                        `;
                                        popup.style.display = 'block';
                                    }} else {{
                                        console.error('Dados da entrada não encontrados.');
                                    }}
                                    }}
                                }});
                            }});
                        }});

                        function filterTable() {{
                            filterBySelect();
                        }}

                        function filterBySelect() {{
                            var userSelect = document.getElementById("userSelect").value.toUpperCase();
                            var projectSelect = document.getElementById("projectSelect").value.toUpperCase();
                            var approvalSelect = document.getElementById("approvalSelect").value.toUpperCase();
                            var table = document.getElementById("time_entries_table");
                            var tr = table.getElementsByTagName("tr");

                            let totalHours = 0;
                            let approvedHours = 0;
                            let repprovedHours = 0;
                            let unapprovedHours = 0;

                            let filteredApproveIds = [];
                            let filteredRejectIds = [];

                            for (var i = 1; i < tr.length; i++) {{
                                tr[i].style.display = "none";
                                var userTd = tr[i].getElementsByTagName("td")[2];
                                var projectTd = tr[i].getElementsByTagName("td")[4];
                                var approvalTd = tr[i].getElementsByTagName("td")[9];
                                if (userTd && projectTd && approvalTd) {{
                                    var userValue = userTd.textContent || userTd.innerText;
                                    var projectValue = projectTd.textContent || projectTd.innerText;
                                    var approvalValue = approvalTd.textContent || approvalTd.innerText;
                                    if ((userSelect === "ALL" || userValue.toUpperCase() === userSelect) &&
                                        (projectSelect === "ALL" || projectValue.toUpperCase() === projectSelect) &&
                                        (approvalSelect === "ALL" || approvalValue.toUpperCase() === approvalSelect)) {{
                                        tr[i].style.display = "";
                                        var entryId = tr[i].getElementsByTagName("td")[0].querySelector("input").value;
                                        var entryHours = parseFloat(tr[i].getElementsByTagName("td")[8].textContent);
                                        totalHours += entryHours;
                                        if (approvalValue === 'Sim') {{
                                            approvedHours += entryHours;

                                        }} else if (approvalValue === 'Não') {{
                                            repprovedHours += entryHours;
                                            filteredApproveIds.push(entryId);

                                        }} else if (approvalValue === 'Pendente') {{
                                            unapprovedHours += entryHours;
                                            filteredApproveIds.push(entryId);
                                            filteredRejectIds.push(entryId);
                                        }}
                                    }}
                                }}
                            }}

                            document.querySelector('.hours-total').textContent = totalHours.toFixed(1);
                            document.querySelector('.hours-approved').textContent = approvedHours.toFixed(1);
                            document.querySelector('.hours-repproved').textContent = repprovedHours.toFixed(1);
                            document.querySelector('.hours-unapproved').textContent = unapprovedHours.toFixed(1);

                            // Atualiza os botões no modo desktop
                            document.querySelector('.btn-approve').setAttribute('onclick', `approveAll('{token}', '${{filteredApproveIds.join(',')}}', {is_client})`);
                            document.querySelector('.btn-reject').setAttribute('onclick', `rejectAll('{token}', '${{filteredRejectIds.join(',')}}', {is_client})`);

                            // Atualiza os botões no modo mobile
                            document.querySelector('.mobile-actions .btn-approve').setAttribute('onclick', `approveAll('{token}', '${{filteredApproveIds.join(',')}}', {is_client})`);
                            document.querySelector('.mobile-actions .btn-reject').setAttribute('onclick', `rejectAll('{token}', '${{filteredRejectIds.join(',')}}', {is_client})`);

                            // Update mobile summary
                            updateMobileSummary();
                        }}

                        function toggleAll(source) {{
                            checkboxes = document.getElementsByName('selected_entries');
                            for(var i=0, n=checkboxes.length;i<n;i++) {{
                                if (!checkboxes[i].disabled) {{
                                    checkboxes[i].checked = source.checked;
                                }}
                            }}
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
                                showAlert('Relatório enviado com sucesso', 'success');
                            }})
                            .catch((error) => {{
                                showAlert('Erro ao enviar o relatório: ' + error, 'error');
                            }});
                        }}

                        function showAlert(message, type) {{
                            var alertDiv = document.createElement('div');
                            alertDiv.className = `alert alert-${type}`;
                            alertDiv.textContent = message;

                            // Estilização básica para o popup
                            alertDiv.style.position = 'fixed';
                            alertDiv.style.top = '20px';
                            alertDiv.style.left = '50%';
                            alertDiv.style.transform = 'translateX(-50%)';
                            alertDiv.style.padding = '10px';
                            alertDiv.style.zIndex = 1000;
                            alertDiv.style.backgroundColor = type === 'success' ? 'green' : 'red';
                            alertDiv.style.color = 'white';
                            alertDiv.style.borderRadius = '5px';
                            alertDiv.style.boxShadow = '0 0 10px rgba(0, 0, 0, 0.1)';
                            alertDiv.style.fontSize = '16px';

                            document.body.appendChild(alertDiv);

                            // Remover o popup após 3 segundos
                            setTimeout(() => {{
                                document.body.removeChild(alertDiv);
                            }}, 3000);
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
                                        id: td[0] && td[0].querySelector("input") ? td[0].querySelector("input").value : "N/A",
                                        date: td[1] ? td[1].textContent : "N/A",
                                        user: td[2] ? td[2].textContent : "N/A",
                                        activity: td[3] ? td[3].textContent : "N/A",
                                        project: td[4] ? td[4].textContent : "N/A",
                                        comments: td[5] ? td[5].textContent : "N/A",
                                        start_time: td[6] ? td[6].textContent : "N/A",
                                        end_time: td[7] ? td[7].textContent : "N/A",
                                        hours: td[8] ? td[8].textContent : "N/A"
                                    }};

                                    data.push(entry);
                                }}
                            }} else {{
                                for (var i = 1; i < tr.length; i++) {{
                                    if (tr[i].style.display !== "none") {{
                                        var td = tr[i].getElementsByTagName("td");

                                        var entry = {{
                                            id: td[0] && td[0].querySelector("input") ? td[0].querySelector("input").value : "N/A",
                                            date: td[1] ? td[1].textContent : "N/A",
                                            user: td[2] ? td[2].textContent : "N/A",
                                            activity: td[3] ? td[3].textContent : "N/A",
                                            project: td[4] ? td[4].textContent : "N/A",
                                            comments: td[5] ? td[5].textContent : "N/A",
                                            start_time: td[6] ? td[6].textContent : "N/A",
                                            end_time: td[7] ? td[7].textContent : "N/A",
                                            hours: td[8] ? td[8].textContent : "N/A"
                                        }};

                                        data.push(entry);
                                    }}
                                }}
                            }}

                            return data;
                        }}

                        function approveAll(token, entryIds, isClient) {{
                            fetch("{API_URL}aprovar_todos?token=" + token + "&entries=" + entryIds + "&client=" + isClient)
                            .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
                            .then(result => {{
                                const status = result.status;
                                const body = result.body;
                                showAlert(body.message, status === 200 ? 'success' : 'error');
                                if (status === 200) {{
                                    location.reload();
                                }}
                            }})
                            .catch(error => {{
                                console.error('Erro:', error);
                                showAlert('Erro ao aprovar horas.', 'error');
                            }});
                        }}

                        function rejectAll(token, entryIds, isClient) {{
                            fetch("{API_URL}reprovar_todos?token=" + token + "&entries=" + entryIds + "&client=" + isClient)
                            .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
                            .then(result => {{
                                const status = result.status;
                                const body = result.body;
                                showAlert(body.message, status === 200 ? 'success' : 'error');
                                if (status === 200) {{
                                    location.reload();
                                }}
                            }})
                            .catch(error => {{
                                console.error('Erro:', error);
                                showAlert('Erro ao reprovar horas.', 'error');
                            }});
                        }}

                        function updateRowsApproval(entryIds, isApproved) {{
                            var table = document.getElementById("time_entries_table");
                            var tr = table.getElementsByTagName("tr");

                            let totalHours = 0;
                            let approvedHours = 0;
                            let repprovedHours = 0;
                            let pendingHours = 0;

                            for (var i = 1; i < tr.length; i++) {{
                                var row = tr[i];
                                var entryId = row.getElementsByTagName("td")[0].querySelector("input").value;
                                var td = row.getElementsByTagName("td");
                                var entryHours = parseFloat(td[8].textContent);
                                var approvalValue = td[9].textContent;

                                if (entryIds.includes(entryId)) {{
                                    if (isApproved && approvalValue !== "Sim") {{
                                        td[9].textContent = "Sim";
                                        approvedHours += entryHours;
                                        if (approvalValue === "Não") {{
                                            repprovedHours -= entryHours;
                                        }} else if (approvalValue === "Pendente") {{
                                            pendingHours -= entryHours;
                                        }}
                                    }} else if (!isApproved && approvalValue !== "Não") {{
                                        td[9].textContent = "Não";
                                        repprovedHours += entryHours;
                                        if (approvalValue === "Sim") {{
                                            approvedHours -= entryHours;
                                        }} else if (approvalValue === "Pendente") {{
                                            pendingHours -= entryHours;
                                        }}
                                    }}
                                    disableRow(entryId);
                                }} else {{
                                    if (approvalValue === "Sim") {{
                                        approvedHours += entryHours;
                                    }} else if (approvalValue === "Não") {{
                                        repprovedHours += entryHours;
                                    }} else if (approvalValue === "Pendente") {{
                                        pendingHours += entryHours;
                                    }}
                                }}
                                totalHours += entryHours;
                            }}

                            document.querySelector('.hours-total').textContent = totalHours.toFixed(1);
                            document.querySelector('.hours-approved').textContent = approvedHours.toFixed(1);
                            document.querySelector('.hours-repproved').textContent = repprovedHours.toFixed(1);
                            document.querySelector('.hours-unapproved').textContent = pendingHours.toFixed(1);

                            // Update mobile summary
                            updateMobileSummary();
                        }}

                        function disableRow(entryId) {{
                            var row = document.getElementById("entry-row-" + entryId);
                            var checkBox = row.querySelector('input[type="checkbox"]');
                            var approveButton = row.querySelector('.btn-approve-table');
                            var rejectButton = row.querySelector('.btn-reject-table');

                            if (checkBox) {{
                                checkBox.disabled = true;
                            }}
                            if (approveButton) {{
                                approveButton.classList.add('disabled');
                            }}
                            if (rejectButton) {{
                                rejectButton.classList.add('disabled');
                            }}
                        }}

                        function showDetailsPopup(entry) {{
                            var popup = document.getElementById('detailsPopup');
                            var content = document.getElementById('popupContent');
                            var horaInicial = entry.custom_fields.find(field => field.name === 'Hora inicial (HH:MM)').value;
                            var horaFinal = entry.custom_fields.find(field => field.name === 'Hora final (HH:MM)').value;
                            var localTrabalho = entry.custom_fields.find(field => field.name === 'Local de trabalho').value;
                            var aprovado = entry.custom_fields.find(field => field.name === 'TS - Aprovado - CLI').value;
                            var approved_value = (aprovado === 'Sim') ? 'Sim' : (aprovado === 'Não') ? 'Não' : 'Pendente';

                            content.innerHTML = `
                                <p><strong>Data:</strong> ${{entry['spent_on']}}</p>
                                <p><strong>Usuário:</strong> ${{entry['user']['name']}}</p>
                                <p><strong>Atividade:</strong> ${{entry['activity']['name']}}</p>
                                <p><strong>Projeto:</strong> ${{entry['project']['name']}}</p>
                                <p><strong>Comentários:</strong> ${{entry['comments']}}</p>
                                <p><strong>Hora Inicial:</strong> ${{horaInicial}}</p>
                                <p><strong>Hora Final:</strong> ${{horaFinal}}</p>
                                <p><strong>Total de Horas:</strong> ${{entry['hours']}}</p>
                                <p><strong>Aprovado:</strong> ${{approved_value}}</p>
                                <div class="btn-group">
                                    <a href="#" onclick="approveHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-approve-table ${{approved_value === 'Sim' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Sim' ? '0' : '1'}};">Aprovar</a>
                                    <a href="#" onclick="rejectHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-reject-table ${{approved_value === 'Não' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Não' ? '0' : '1'}};">Reprovar</a>
                                </div>
                            `;
                            popup.style.display = 'block';
                        }}

                        function hideDetailsPopup() {{
                            var popup = document.getElementById('detailsPopup');
                            popup.style.display = 'none';
                        }}

                        function updateMobileSummary() {{
                            document.querySelector('.hours-total-mobile').textContent = document.querySelector('.hours-total').textContent;
                            document.querySelector('.hours-approved-mobile').textContent = document.querySelector('.hours-approved').textContent;
                            document.querySelector('.hours-repproved-mobile').textContent = document.querySelector('.hours-repproved').textContent;
                            document.querySelector('.hours-unapproved-mobile').textContent = document.querySelector('.hours-unapproved').textContent;
                        }}

                        // Ensure initial values are set for mobile view
                        document.addEventListener('DOMContentLoaded', function() {{
                            updateMobileSummary();
                        }});
                    </script>
                </body>
                </html>
                '''

                # Render the HTML template
                return render_template_string(html_template)


        else:
            logger.error(
                f"Erro ao buscar entradas de tempo para o usuário ID {user_id}: {entries_response.status_code}")
            return render_response("Erro ao buscar entradas de tempo", 500)

    except requests.exceptions.RequestException as e:
        logger.error(f"Erro de conexão ao buscar usuário com ID {user_id}: {e}")
        return render_response("Erro de conexão", 500)


def create_html_table_client(time_entries, recipient):
    total_hours = 0  # Variável para somar as horas
    approved_hours = 0  # Variável para somar as horas aprovadas
    unapproved_hours = 0  # Variável para somar as horas não aprovadas
    repproved_hours = 0

    table = '''
    <div">
      <div class="filters-container">
        <!-- Coloque aqui os elementos do filtro -->
      </div>
      <div class="table-wrapper">
        <div style="overflow-x:auto;" class="table-container">
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
                (field['value'] for field in entry['custom_fields'] if field['name'] == 'Hora final (HH:MM)'), '')
            project_name = entry['project']['name'] if 'project' in entry else 'N/A'
            is_client = 1 if 'client' in request.full_path else 0

            total_hours += entry['hours']
            approved = any(
                field['name'] == 'TS - Aprovado - CLI' and (field['value'] == '1') for field in entry['custom_fields'])

            repproved = any(
                field['name'] == 'TS - Aprovado - CLI' and (field['value'] == '0') for field in entry['custom_fields'])

            unnaproved = any(
                field['name'] == 'TS - Aprovado - CLI' and field['value'] == '' for field in entry['custom_fields']
            )

            if approved:
                approved_hours += entry['hours']
                aprovado = 'Sim'
                disable_attr = 'disabled'
            elif repproved:
                repproved_hours += entry['hours']
                aprovado = 'Não'
                disable_attr = ''
            elif unnaproved:
                unapproved_hours += entry['hours']
                aprovado = 'Pendente'
                disable_attr = ''
            else:
                unapproved_hours += entry['hours']
                aprovado = 'Pendente'
                disable_attr = ''
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
              <td class="hours-value">{entry['hours']}</td>
              <td class="approved-value">{aprovado}</td>
              <td>
                <a href="#" onclick="approveHour({entry['id']}, '{request.args.get('token')}', {is_client}, {entry['hours']}, '{aprovado}')" class="btn btn-approve-table {'disabled' if approved else ''}" style="opacity:{'0' if approved else '1'};">Aprovar</a>
                <a href="#" onclick="rejectHour({entry['id']}, '{request.args.get('token')}', {is_client}, {entry['hours']}, '{aprovado}')" class="btn btn-reject-table {'disabled' if approved else ''}" style="opacity:{'0' if approved else '1'};">Reprovar</a>
              </td>
            </tr>
            '''

    table += f'''
          </tbody>
        </table>
      </div>
      <br>
      </div>
      <div id="hours-summary-table" class="hours-summary">
        <p>Total de Horas: <span class="hours-total">{total_hours}</span></p>
        <p>Total de Horas Aprovadas: <span class="hours-approved">{approved_hours}</span></p>
        <p>Total de Horas Reprovadas: <span class="hours-repproved">{repproved_hours}</span></p>
        <p>Total de Horas Pendentes de Aprovação: <span class="hours-unapproved">{unapproved_hours}</span></p>
      </div>
    '''

    table += f'''
    <style>
      .table-wrapper {{
        width: 100%;
        overflow-x: auto;
      }}
      .table-container {{
        max-height: 450px;
        width: 100%;
      }}
      .table-container th:nth-child(11), .table-container td:nth-child(11) {{
        width: 80px; /* Define uma largura menor para a coluna "Ações" */
        text-align: center; /* Centraliza o texto e os botões na coluna */
      }}
      .hours-summary {{
        font-size: 1.2em;
        font-weight: bold;
        color: #333;
        margin-top: 10px;
      }}
      .hours-summary p {{
        margin: 5px 0;
      }}
      .hours-total, .hours-approved, .hours-unapproved {{
        color: #1E90FF;
      }}
      .hours-approved {{
        color: #28a745;
      }}
      .hours-repproved {{
        color: #dc3545;
      }}
      .hours-unapproved {{
        color: #bbdb03;
      }}
      thead th {{
        position: sticky;
        top: 0;
        background: white;
        z-index: 10;
        box-shadow: 0 2px 2px -1px rgba(0, 0, 0, 0.4);
        padding: 8px 4px;
        min-height: 10px;
        text-align: center;
      }}
      .table-container td {{
        white-space: nowrap;
      }}
      .btn {{
        display: inline-block;
        margin-right: 5px;
      }}
      .btn-approve-table, .btn-reject-table {{
        display: inline-block;
        width: 70px;
        margin-right: 2px;
        text-align: center;
        font-size: 0.8em;
        padding: 5px;
      }}
      .btn-approve-table {{
        background-color: #28a745;
        color: white;
        margin-bottom: 2px;
      }}
      .btn-reject-table {{
        background-color: #dc3545;
        color: white;
        margin-top: 2px;
      }}
      .btn.disabled {{
        visibility: hidden;
      }}
      .filter-fields-style {{
            display: flex;
            flex-direction: column;
            gap: 15px;
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            margin-top: 15px;
        }}
        
        .filter-fields-style label {{
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }}
        
        .filter-fields-style input[type="text"],
        .filter-fields-style select {{
            width: 20%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 14px;
        }}
        
        .filter-fields-style select {{
            appearance: none;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAiIGhlaWdodD0iNSIgdmlld0JveD0iMCAwIDEwIDUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZmlsbD0iI0NDQyIgZD0iTTAgMGw1IDUgNS01eiIgLz48L3N2Zz4=') no-repeat right 10px center;
            background-size: 10px 5px;
            -webkit-appearance: none;
            -moz-appearance: none;
            appearance: none;
        }}
        
        .filter-fields-style input[type="text"]::placeholder {{
            color: #aaa;
            font-style: italic;
        }}
      @media (max-width: 768px) {{
     

        #time_entries_form {{
            display: flex;
            flex-direction: column;
            gap: 10px;
            width: 100%;
        }}

        .filters label {{
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .filters input, .filters select {{
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }}
        .container {{
            padding: 10px;
            overflow-y: auto;
            max-height: 80vh;
        }}
        .header-logo h1 {{
            font-size: 1.5em;
        }}
        .filters {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 0;
            padding: 0;
        }}
        .table-wrapper {{
            overflow-x: auto;
        }}
        .table-container {{
            font-size: 0.9em;
            overflow-x: scroll;
        }}
        .btn-group {{
            flex-direction: column;
            align-items: center;
        }}
        .btn-group .btn-relatorio {{
            width: 180px;
            height: 40px;
            margin: 0px 0;
        }}
        .filter-fields-style {{
            display: flex;
            flex-direction: column;
            gap: 15px;
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            margin-top: 15px;
        }}
        
        .filter-fields-style label {{
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }}
        
        .filter-fields-style input[type="text"],
        .filter-fields-style select {{
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 14px;
        }}
        
        .filter-fields-style select {{
            appearance: none;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAiIGhlaWdodD0iNSIgdmlld0JveD0iMCAwIDEwIDUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZmlsbD0iI0NDQyIgZD0iTTAgMGw1IDUgNS01eiIgLz48L3N2Zz4=') no-repeat right 10px center;
            background-size: 10px 5px;
            -webkit-appearance: none;
            -moz-appearance: none;
            appearance: none;
        }}
        
        .filter-fields-style input[type="text"]::placeholder {{
            color: #aaa;
            font-style: italic;
        }}

    }}
    
    </style>
    '''

    table += f'''
    <script>
        function toggleFilters() {{
            var form = document.getElementById("time_entries_form");
                            var xpath = "//*[@id='filter-fields']";
                            var result = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
                            var filterFields = result.singleNodeValue;

                            if (form.style.display === "none" || form.style.display === "") {{
                                form.style.display = "block";
                                filterFields.style.display = "block";  // Certifique-se de que os campos de filtro também estejam visíveis
                            }} else {{
                                form.style.display = "none";
                                filterFields.style.display = "none";  // Certifique-se de que os campos de filtro também estejam escondidos
                            }}
        }}
    
        function toggleFieldset(legend) {{
            var fieldset = legend.parentElement;
            var div = fieldset.querySelector('div');
            if (div.style.display === "none" || div.style.display === "") {{
                div.style.display = "block";
            }} else {{
                div.style.display = "none";
            }}
        }}
      function approveHour(entryId, token, isClient, entryHours, currentStatus) {{
        fetch("{API_URL}aprovar_hora?id=" + entryId + "&token=" + token + "&client=" + isClient)
        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
        .then(result => {{
          const status = result.status;
          const body = result.body;
          if (status === 200) {{
            showAlert('Hora aprovada com sucesso!', 'success');
            updateRowApproval(entryId, true, entryHours);
            updateHourSummary(entryHours, 'approve', currentStatus);
          }} else {{
            showAlert(body.message, 'error');
          }}
        }})
        .catch(error => {{
          console.error('Erro:', error);
          showAlert('Erro ao aprovar hora.', 'error');
        }});
      }}

      function rejectHour(entryId, token, isClient, entryHours, currentStatus) {{
        fetch("{API_URL}reprovar_hora?id=" + entryId + "&token=" + token + "&client=" + isClient)
        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
        .then(result => {{
          const status = result.status;
          const body = result.body;
          if (status === 200) {{
            showAlert('Hora reprovada com sucesso!', 'success');
            updateRowApproval(entryId, false, entryHours);
            updateHourSummary(entryHours, 'reject', currentStatus);
          }} else {{
            showAlert(body.message, 'error');
          }}
        }})
        .catch(error => {{
          console.error('Erro:', error);
          showAlert('Erro ao reprovar hora.', 'error');
        }});
      }}

      function updateHourSummary(entryHours, action, currentStatus) {{
        const totalHoursElem = document.querySelector('.hours-total');
        const approvedHoursElem = document.querySelector('.hours-approved');
        const unapprovedHoursElem = document.querySelector('.hours-unapproved');
        const repprovedHoursElem = document.querySelector('.hours-repproved');

        let totalHours = parseFloat(totalHoursElem.textContent);
        let approvedHours = parseFloat(approvedHoursElem.textContent);
        let unapprovedHours = parseFloat(unapprovedHoursElem.textContent);
        let repprovedHours = parseFloat(repprovedHoursElem.textContent);

        if (currentStatus === 'Sim' && action === 'approve') {{
          // Não faz alteração
        }} else if (currentStatus === 'Sim' && action === 'reject') {{
          approvedHours -= entryHours;
          repprovedHours += entryHours;
        }} else if (currentStatus === 'Não' && action === 'approve') {{
          repprovedHours -= entryHours;
          approvedHours += entryHours;
        }} else if (currentStatus === 'Não' && action === 'reject') {{
          // Não faz alteração
        }} else if (currentStatus === 'Pendente' && action === 'approve') {{
          unapprovedHours -= entryHours;
          approvedHours += entryHours;
        }} else if (currentStatus === 'Pendente' && action === 'reject') {{
          unapprovedHours -= entryHours;
          repprovedHours += entryHours;
        }}

        totalHoursElem.textContent = totalHours.toFixed(1);
        approvedHoursElem.textContent = approvedHours.toFixed(1);
        unapprovedHoursElem.textContent = unapprovedHours.toFixed(1);
        repprovedHoursElem.textContent = repprovedHours.toFixed(1);
      }}

      function updateRowApproval(entryId, isApproved, entryHours) {{
        var row = document.getElementById("entry-row-" + entryId);
        var approveButton = row.querySelector('.btn-approve-table');
        var rejectButton = row.querySelector('.btn-reject-table');
        var approvedCell = row.querySelector('.approved-value');

        if (approveButton) {{
          approveButton.classList.add('disabled');
        }}
        if (rejectButton) {{
          rejectButton.classList.add('disabled');
        }}
        if (approvedCell) {{
          approvedCell.textContent = isApproved ? 'Sim' : 'Não';
        }}
      }}

      function toggleAll(source) {{
        var checkboxes = document.getElementsByName('selected_entries');
        for (var i = 0, n = checkboxes.length; i < n; i++) {{
          if (!checkboxes[i].disabled) {{
            checkboxes[i].checked = source.checked;
          }}
        }}
      }}

      function showAlert(message, type) {{
        var alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type}`;
        alertDiv.textContent = message;

        alertDiv.style.position = 'fixed';
        alertDiv.style.top = '20px';
        alertDiv.style.left = '50%';
        alertDiv.style.transform = 'translateX(-50%)';
        alertDiv.style.padding = '10px';
        alertDiv.style.zIndex = 1000;
        alertDiv.style.backgroundColor = type === 'success' ? 'green' : 'red';
        alertDiv.style.color = 'white';
        alertDiv.style.borderRadius = '5px';
        alertDiv.style.boxShadow = '0 0 10px rgba(0, 0, 0, 0.1)';
        alertDiv.style.fontSize = '16px';

        document.body.appendChild(alertDiv);

        setTimeout(() => {{
            document.body.removeChild(alertDiv);
        }}, 3000);
      }}
    </script>
    '''

    return table


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
        project_name = request.args.get('project')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        is_client = 1 if 'client' in request.full_path else 0

        # Definir datas padrão (mês atual) se não fornecidas
        if not start_date or not end_date:
            today = datetime.today()
            first_day_of_month = today.replace(day=1)
            last_day_of_month = today.replace(day=calendar.monthrange(today.year, today.month)[1])
            start_date = first_day_of_month.strftime('%Y-%m-%d')
            end_date = last_day_of_month.strftime('%Y-%m-%d')

        # Construir URL de requisição com filtros
        url = f'{REDMINE_URL}/time_entries.json?user_id={user_id}&from={start_date}&to={end_date}'


        entries_response = requests.get(url, headers={
            'X-Redmine-API-Key': REDMINE_API_KEY,
            'Content-Type': 'application/json'
        }, verify=False)

        if entries_response.ok:
            # Filtra as entradas de tempo para incluir apenas aquelas que não foram aprovadas
            time_entries = entries_response.json().get('time_entries', [])
            unapproved_entries = [entry for entry in time_entries if any(
                field['name'] == 'TS - Aprovado - EVT' and (field['value'] == '0' or field['value'] == '') for field in
                entry.get('custom_fields', []))]

            if not unapproved_entries:
                logger.warning(
                    f"Nenhuma entrada de tempo não aprovada encontrada para o usuário ID {user_id} no período de {start_date} a {end_date}")

            table_html = create_html_table(time_entries)
            # Obtém o token da URL atual

            token = request.args.get('token')
            # Constrói a lista de IDs das entradas
            entry_ids = ','.join([str(entry['id']) for entry in unapproved_entries])
            approve_entry_ids = ','.join(
                [str(entry['id']) for entry in unapproved_entries if
                 any(field['name'] == 'TS - Aprovado - EVT' and (field['value'] == '0' or field['value'] == '') for
                     field in entry.get('custom_fields', []))]
            )
            reject_entry_ids = ','.join(
                [str(entry['id']) for entry in unapproved_entries if
                 any(field['name'] == 'TS - Aprovado - EVT' and (field['value'] == '1' or field['value'] == '') for
                     field in entry.get('custom_fields', []))]
            )
            # Extrai usuários e projetos para os filtros
            usuarios = {entry['user']['name'] for entry in time_entries}
            projetos = {entry['project']['name'] for entry in time_entries}

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
                                        var isCollapsed = fieldset.classList.toggle('collapsed');
                                        var div = fieldset.querySelector('div');
                                        var arrow = legend.querySelector('.arrow');
                                        if (isCollapsed) {{
                                            div.style.display = 'none';
                                            arrow.innerHTML = '▼';  // Seta para a direita
                                        }} else {{
                                            div.style.display = 'block';
                                            arrow.innerHTML = '▶';  // Seta para baixo
                                        }}
                                    }}

                                    document.addEventListener('DOMContentLoaded', function() {{
                                        // Lógica de seleção automática de projetos e filtros

                                        const projectSelect = document.getElementById('projectSelect');
                                        const project_name = "{project_name}";
                                        if (projectSelect && project_name) {{
                                            const options = projectSelect.options;
                                            for (let i = 0; i < options.length; i++) {{
                                                if (options[i].text.toUpperCase() === project_name.toUpperCase()) {{
                                                    projectSelect.selectedIndex = i;
                                                    filterBySelect();
                                                    break;
                                                }}
                                            }}
                                        }}

                                        document.getElementById("filterInput").addEventListener("keyup", function() {{
                                            filterBySelect();
                                        }});

                                        document.getElementById("userSelect").addEventListener("change", function() {{
                                            filterBySelect();
                                        }});

                                        document.getElementById("projectSelect").addEventListener("change", function() {{
                                            filterBySelect();
                                        }});

                                        document.getElementById("approvalSelect").addEventListener("change", function() {{
                                            filterBySelect();
                                        }});

                                        const tableRows = document.querySelectorAll('#time_entries_table tbody tr');

                                        tableRows.forEach(row => {{
                                            row.addEventListener('click', function() {{
                                            if (window.innerWidth <= 768) {{
                                                var entryData = {{
                                                    spent_on: row.cells[1].textContent.trim(),
                                                    user: {{ name: row.cells[2].textContent.trim() }},
                                                    activity: {{ name: row.cells[3].textContent.trim() }},
                                                    project: {{ name: row.cells[4].textContent.trim() }},
                                                    comments: row.cells[5].textContent.trim(),
                                                    custom_fields: [
                                                        {{ name: 'Hora inicial (HH:MM)', value: row.cells[6].textContent.trim() }},
                                                        {{ name: 'Hora final (HH:MM)', value: row.cells[7].textContent.trim() }},
                                                        {{ name: 'Local de trabalho', value: 'Indisponível' }},
                                                        {{ name: 'TS - Aprovado - CLI', value: row.cells[9].textContent.trim() }}
                                                    ],
                                                    hours: row.cells[8].textContent.trim(),
                                                    id: row.id.split('-')[2]
                                                }};
                                                if (entryData) {{
                                                    var entry = entryData;

                                                    var popup = document.getElementById('detailsPopup');
                                                    var content = document.getElementById('popupContent');

                                                    var horaInicial = entry.custom_fields.find(field => field.name === 'Hora inicial (HH:MM)').value;
                                                    var horaFinal = entry.custom_fields.find(field => field.name === 'Hora final (HH:MM)').value;
                                                    var localTrabalho = entry.custom_fields.find(field => field.name === 'Local de trabalho').value;
                                                    var aprovado = entry.custom_fields.find(field => field.name === 'TS - Aprovado - CLI').value;
                                                    var approved_value = (aprovado === '1') ? 'Sim' : (aprovado === '0') ? 'Não' : 'Pendente';

                                                    content.innerHTML = `
                                                        <p><strong>Data:</strong> ${{entry['spent_on']}}</p>
                                                        <p><strong>Usuário:</strong> ${{entry['user']['name']}}</p>
                                                        <p><strong>Atividade:</strong> ${{entry['activity']['name']}}</p>
                                                        <p><strong>Projeto:</strong> ${{entry['project']['name']}}</p>
                                                        <p><strong>Comentários:</strong> ${{entry['comments']}}</p>
                                                        <p><strong>Hora Inicial:</strong> ${{horaInicial}}</p>
                                                        <p><strong>Hora Final:</strong> ${{horaFinal}}</p>
                                                        <p><strong>Total de Horas:</strong> ${{entry['hours']}}</p>
                                                        <p><strong>Aprovado:</strong> ${{aprovado}}</p>
                                                        <div class="btn-group">
                                                            <a href="#" onclick="approveHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{aprovado}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-approve-table ${{aprovado === 'Sim' ? 'disabled' : ''}}" style="opacity:${{aprovado === 'Sim' ? '0' : '1'}};">Aprovar</a>
                                                            <a href="#" onclick="rejectHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{aprovado}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-reject-table ${{aprovado === 'Sim' ? 'disabled' : ''}}" style="opacity:${{aprovado === 'Sim' ? '0' : '1'}};">Reprovar</a>
                                                        </div>
                                                    `;
                                                    popup.style.display = 'block';
                                                }} else {{
                                                    console.error('Dados da entrada não encontrados.');
                                                }}
                                                }}
                                            }});
                                        }});
                                    }});

                                    function filterTable() {{
                                        filterBySelect();
                                    }}

                                    function filterBySelect() {{
                                        var userSelect = document.getElementById("userSelect").value.toUpperCase();
                                        var projectSelect = document.getElementById("projectSelect").value.toUpperCase();
                                        var approvalSelect = document.getElementById("approvalSelect").value.toUpperCase();
                                        var table = document.getElementById("time_entries_table");
                                        var tr = table.getElementsByTagName("tr");

                                        let totalHours = 0;
                                        let approvedHours = 0;
                                        let repprovedHours = 0;
                                        let unapprovedHours = 0;

                                        let filteredApproveIds = [];
                                        let filteredRejectIds = [];

                                        for (var i = 1; i < tr.length; i++) {{
                                            tr[i].style.display = "none";
                                            var userTd = tr[i].getElementsByTagName("td")[2];
                                            var projectTd = tr[i].getElementsByTagName("td")[4];
                                            var approvalTd = tr[i].getElementsByTagName("td")[9];
                                            if (userTd && projectTd && approvalTd) {{
                                                var userValue = userTd.textContent || userTd.innerText;
                                                var projectValue = projectTd.textContent || projectTd.innerText;
                                                var approvalValue = approvalTd.textContent || approvalTd.innerText;
                                                if ((userSelect === "ALL" || userValue.toUpperCase() === userSelect) &&
                                                    (projectSelect === "ALL" || projectValue.toUpperCase() === projectSelect) &&
                                                    (approvalSelect === "ALL" || approvalValue.toUpperCase() === approvalSelect)) {{
                                                    tr[i].style.display = "";
                                                    var entryId = tr[i].getElementsByTagName("td")[0].querySelector("input").value;
                                                    var entryHours = parseFloat(tr[i].getElementsByTagName("td")[8].textContent);
                                                    totalHours += entryHours;
                                                    if (approvalValue === 'Sim') {{
                                                        approvedHours += entryHours;

                                                    }} else if (approvalValue === 'Não') {{
                                                        repprovedHours += entryHours;
                                                        filteredApproveIds.push(entryId);

                                                    }} else if (approvalValue === 'Pendente') {{
                                                        unapprovedHours += entryHours;
                                                        filteredApproveIds.push(entryId);
                                                        filteredRejectIds.push(entryId);
                                                    }}
                                                }}
                                            }}
                                        }}

                                        document.querySelector('.hours-total').textContent = totalHours.toFixed(1);
                                        document.querySelector('.hours-approved').textContent = approvedHours.toFixed(1);
                                        document.querySelector('.hours-repproved').textContent = repprovedHours.toFixed(1);
                                        document.querySelector('.hours-unapproved').textContent = unapprovedHours.toFixed(1);

                                        // Atualiza os botões no modo desktop
                                        document.querySelector('.btn-approve').setAttribute('onclick', `approveAll('{token}', '${{filteredApproveIds.join(',')}}', {is_client})`);
                                        document.querySelector('.btn-reject').setAttribute('onclick', `rejectAll('{token}', '${{filteredRejectIds.join(',')}}', {is_client})`);

                                        // Atualiza os botões no modo mobile
                                        document.querySelector('.mobile-actions .btn-approve').setAttribute('onclick', `approveAll('{token}', '${{filteredApproveIds.join(',')}}', {is_client})`);
                                        document.querySelector('.mobile-actions .btn-reject').setAttribute('onclick', `rejectAll('{token}', '${{filteredRejectIds.join(',')}}', {is_client})`);

                                        // Update mobile summary
                                        updateMobileSummary();
                                    }}

                                    function toggleAll(source) {{
                                        checkboxes = document.getElementsByName('selected_entries');
                                        for(var i=0, n=checkboxes.length;i<n;i++) {{
                                            if (!checkboxes[i].disabled) {{
                                                checkboxes[i].checked = source.checked;
                                            }}
                                        }}
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
                                            showAlert('Relatório enviado com sucesso', 'success');
                                        }})
                                        .catch((error) => {{
                                            showAlert('Erro ao enviar o relatório: ' + error, 'error');
                                        }});
                                    }}

                                    function showAlert(message, type) {{
                                        var alertDiv = document.createElement('div');
                                        alertDiv.className = `alert alert-${type}`;
                                        alertDiv.textContent = message;

                                        // Estilização básica para o popup
                                        alertDiv.style.position = 'fixed';
                                        alertDiv.style.top = '20px';
                                        alertDiv.style.left = '50%';
                                        alertDiv.style.transform = 'translateX(-50%)';
                                        alertDiv.style.padding = '10px';
                                        alertDiv.style.zIndex = 1000;
                                        alertDiv.style.backgroundColor = type === 'success' ? 'green' : 'red';
                                        alertDiv.style.color = 'white';
                                        alertDiv.style.borderRadius = '5px';
                                        alertDiv.style.boxShadow = '0 0 10px rgba(0, 0, 0, 0.1)';
                                        alertDiv.style.fontSize = '16px';

                                        document.body.appendChild(alertDiv);

                                        // Remover o popup após 3 segundos
                                        setTimeout(() => {{
                                            document.body.removeChild(alertDiv);
                                        }}, 3000);
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
                                                    id: td[0] && td[0].querySelector("input") ? td[0].querySelector("input").value : "N/A",
                                                    date: td[1] ? td[1].textContent : "N/A",
                                                    user: td[2] ? td[2].textContent : "N/A",
                                                    activity: td[3] ? td[3].textContent : "N/A",
                                                    project: td[4] ? td[4].textContent : "N/A",
                                                    comments: td[5] ? td[5].textContent : "N/A",
                                                    start_time: td[6] ? td[6].textContent : "N/A",
                                                    end_time: td[7] ? td[7].textContent : "N/A",
                                                    hours: td[8] ? td[8].textContent : "N/A"
                                                }};

                                                data.push(entry);
                                            }}
                                        }} else {{
                                            for (var i = 1; i < tr.length; i++) {{
                                                if (tr[i].style.display !== "none") {{
                                                    var td = tr[i].getElementsByTagName("td");

                                                    var entry = {{
                                                        id: td[0] && td[0].querySelector("input") ? td[0].querySelector("input").value : "N/A",
                                                        date: td[1] ? td[1].textContent : "N/A",
                                                        user: td[2] ? td[2].textContent : "N/A",
                                                        activity: td[3] ? td[3].textContent : "N/A",
                                                        project: td[4] ? td[4].textContent : "N/A",
                                                        comments: td[5] ? td[5].textContent : "N/A",
                                                        start_time: td[6] ? td[6].textContent : "N/A",
                                                        end_time: td[7] ? td[7].textContent : "N/A",
                                                        hours: td[8] ? td[8].textContent : "N/A"
                                                    }};

                                                    data.push(entry);
                                                }}
                                            }}
                                        }}

                                        return data;
                                    }}

                                    function approveAll(token, entryIds, isClient) {{
                                        fetch("{API_URL}aprovar_todos?token=" + token + "&entries=" + entryIds + "&client=" + isClient)
                                        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
                                        .then(result => {{
                                            const status = result.status;
                                            const body = result.body;
                                            showAlert(body.message, status === 200 ? 'success' : 'error');
                                            if (status === 200) {{
                                                location.reload();
                                            }}
                                        }})
                                        .catch(error => {{
                                            console.error('Erro:', error);
                                            showAlert('Erro ao aprovar horas.', 'error');
                                        }});
                                    }}

                                    function rejectAll(token, entryIds, isClient) {{
                                        fetch("{API_URL}reprovar_todos?token=" + token + "&entries=" + entryIds + "&client=" + isClient)
                                        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
                                        .then(result => {{
                                            const status = result.status;
                                            const body = result.body;
                                            showAlert(body.message, status === 200 ? 'success' : 'error');
                                            if (status === 200) {{
                                                location.reload();
                                            }}
                                        }})
                                        .catch(error => {{
                                            console.error('Erro:', error);
                                            showAlert('Erro ao reprovar horas.', 'error');
                                        }});
                                    }}

                                    function updateRowsApproval(entryIds, isApproved) {{
                                        var table = document.getElementById("time_entries_table");
                                        var tr = table.getElementsByTagName("tr");

                                        let totalHours = 0;
                                        let approvedHours = 0;
                                        let repprovedHours = 0;
                                        let pendingHours = 0;

                                        for (var i = 1; i < tr.length; i++) {{
                                            var row = tr[i];
                                            var entryId = row.getElementsByTagName("td")[0].querySelector("input").value;
                                            var td = row.getElementsByTagName("td");
                                            var entryHours = parseFloat(td[8].textContent);
                                            var approvalValue = td[9].textContent;

                                            if (entryIds.includes(entryId)) {{
                                                if (isApproved && approvalValue !== "Sim") {{
                                                    td[9].textContent = "Sim";
                                                    approvedHours += entryHours;
                                                    if (approvalValue === "Não") {{
                                                        repprovedHours -= entryHours;
                                                    }} else if (approvalValue === "Pendente") {{
                                                        pendingHours -= entryHours;
                                                    }}
                                                }} else if (!isApproved && approvalValue !== "Não") {{
                                                    td[9].textContent = "Não";
                                                    repprovedHours += entryHours;
                                                    if (approvalValue === "Sim") {{
                                                        approvedHours -= entryHours;
                                                    }} else if (approvalValue === "Pendente") {{
                                                        pendingHours -= entryHours;
                                                    }}
                                                }}
                                                disableRow(entryId);
                                            }} else {{
                                                if (approvalValue === "Sim") {{
                                                    approvedHours += entryHours;
                                                }} else if (approvalValue === "Não") {{
                                                    repprovedHours += entryHours;
                                                }} else if (approvalValue === "Pendente") {{
                                                    pendingHours += entryHours;
                                                }}
                                            }}
                                            totalHours += entryHours;
                                        }}

                                        document.querySelector('.hours-total').textContent = totalHours.toFixed(1);
                                        document.querySelector('.hours-approved').textContent = approvedHours.toFixed(1);
                                        document.querySelector('.hours-repproved').textContent = repprovedHours.toFixed(1);
                                        document.querySelector('.hours-unapproved').textContent = pendingHours.toFixed(1);

                                        // Update mobile summary
                                        updateMobileSummary();
                                    }}

                                    function disableRow(entryId) {{
                                        var row = document.getElementById("entry-row-" + entryId);
                                        var checkBox = row.querySelector('input[type="checkbox"]');
                                        var approveButton = row.querySelector('.btn-approve-table');
                                        var rejectButton = row.querySelector('.btn-reject-table');

                                        if (checkBox) {{
                                            checkBox.disabled = true;
                                        }}
                                        if (approveButton) {{
                                            approveButton.classList.add('disabled');
                                        }}
                                        if (rejectButton) {{
                                            rejectButton.classList.add('disabled');
                                        }}
                                    }}

                                    function showDetailsPopup(entry) {{
                                        var popup = document.getElementById('detailsPopup');
                                        var content = document.getElementById('popupContent');
                                        var horaInicial = entry.custom_fields.find(field => field.name === 'Hora inicial (HH:MM)').value;
                                        var horaFinal = entry.custom_fields.find(field => field.name === 'Hora final (HH:MM)').value;
                                        var localTrabalho = entry.custom_fields.find(field => field.name === 'Local de trabalho').value;
                                        var aprovado = entry.custom_fields.find(field => field.name === 'TS - Aprovado - CLI').value;
                                        var approved_value = (aprovado === 'Sim') ? 'Sim' : (aprovado === 'Não') ? 'Não' : 'Pendente';

                                        content.innerHTML = `
                                            <p><strong>Data:</strong> ${{entry['spent_on']}}</p>
                                            <p><strong>Usuário:</strong> ${{entry['user']['name']}}</p>
                                            <p><strong>Atividade:</strong> ${{entry['activity']['name']}}</p>
                                            <p><strong>Projeto:</strong> ${{entry['project']['name']}}</p>
                                            <p><strong>Comentários:</strong> ${{entry['comments']}}</p>
                                            <p><strong>Hora Inicial:</strong> ${{horaInicial}}</p>
                                            <p><strong>Hora Final:</strong> ${{horaFinal}}</p>
                                            <p><strong>Total de Horas:</strong> ${{entry['hours']}}</p>
                                            <p><strong>Aprovado:</strong> ${{approved_value}}</p>
                                            <div class="btn-group">
                                                <a href="#" onclick="approveHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-approve-table ${{approved_value === 'Sim' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Sim' ? '0' : '1'}};">Aprovar</a>
                                                <a href="#" onclick="rejectHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-reject-table ${{approved_value === 'Não' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Não' ? '0' : '1'}};">Reprovar</a>
                                            </div>
                                        `;
                                        popup.style.display = 'block';
                                    }}

                                    function hideDetailsPopup() {{
                                        var popup = document.getElementById('detailsPopup');
                                        popup.style.display = 'none';
                                    }}

                                    function updateMobileSummary() {{
                                        document.querySelector('.hours-total-mobile').textContent = document.querySelector('.hours-total').textContent;
                                        document.querySelector('.hours-approved-mobile').textContent = document.querySelector('.hours-approved').textContent;
                                        document.querySelector('.hours-repproved-mobile').textContent = document.querySelector('.hours-repproved').textContent;
                                        document.querySelector('.hours-unapproved-mobile').textContent = document.querySelector('.hours-unapproved').textContent;
                                    }}

                                    // Ensure initial values are set for mobile view
                                    document.addEventListener('DOMContentLoaded', function() {{
                                        updateMobileSummary();
                                        if (window.innerWidth <= 768) {{ // Verifica se a largura da janela é de 768px ou menos (modo mobile)
                                            var columnsToHide = [4, 5, 6, 11]; // Índices das colunas a serem escondidas
                                            columnsToHide.forEach(function(index) {{
                                                var thXPath = `//*[@id="time_entries_table"]/thead/tr/th[${{index}}]`;
                                                var th = document.evaluate(thXPath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                                                if (th) th.style.display = 'none';

                                                var tdXPath = `//*[@id="time_entries_table"]/tbody/tr/td[${{index}}]`;
                                                var tds = document.evaluate(tdXPath, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
                                                for (var i = 0; i < tds.snapshotLength; i++) {{
                                                    tds.snapshotItem(i).style.display = 'none';
                                                }}
                                            }});
                                            var thHoraInicial = document.querySelector('#time_entries_table thead tr th:nth-child(7)');
                                            if (thHoraInicial) {{
                                                thHoraInicial.textContent = 'Hora Inicial';
                                            }}

                                            var thHoraFinal = document.querySelector('#time_entries_table thead tr th:nth-child(8)');
                                            if (thHoraFinal) {{
                                                thHoraFinal.textContent = 'Hora Final';
                                            }}
                                            var thTotalHoras = document.querySelector('#time_entries_table thead tr th:nth-child(9)');
                                            if (thTotalHoras) {{
                                                thTotalHoras.textContent = 'Total Horas';
                                            }}
                                            
                                        }}
                                    }});
                                </script>
                                <style>
                                    body {{
                                        overflow-y: auto; /* Adiciona a barra de rolagem vertical ao body */
                                        margin: 0;
                                        padding: 0;
                                    }}
                                    #header {{
                                        position: fixed;
                                        top: 0;
                                        width: 100%;
                                        z-index: 10; /* Garante que o header fique sobre outros elementos */
                                        background-color: #333333; /* Defina a cor de fundo original aqui */
                                        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1); /* Adicione uma sombra para o header */
                                    }}
                                    .container {{
                                        display: flex;
                                        flex-direction: column;
                                        margin-top: 60px; /* Espaço para o header fixo */
                                    }}
                                    .table-container th:nth-child(11), .table-container td:nth-child(11) {{
                                        width: 100px; /* Define uma largura menor para a coluna "Ações" */
                                        text-align: center; /* Centraliza o texto e os botões na coluna */
                                    }}
                                    .filters-container {{
                                        display: flex;
                                        flex-direction: column;
                                        align-items: stretch;
                                        width: 100%;
                                    }}

                                    .toggle-filters {{
                                        background-color: #1E90FF;
                                        color: white;
                                        padding: 10px;
                                        text-align: center;
                                        border: none;
                                        border-radius: 5px;
                                        margin-bottom: 10px;
                                        width: 100%;
                                        max-width: 200px;
                                        align-self: center;
                                    }}

                                    #time_entries_form {{
                                        display: flex;
                                        flex-direction: column;
                                        gap: 10px;
                                        width: 100%;
                                    }}

                                    #filter-fields {{
                                        display: flex;
                                        flex-direction: column;
                                        gap: 10px;
                                    }}

                                    .filters label {{
                                        font-weight: bold;
                                        margin-bottom: 5px;
                                    }}

                                    .filters input, .filters select {{
                                        width: 100%;
                                        padding: 10px;
                                        border: 1px solid #ddd;
                                        border-radius: 5px;
                                    }}

                                    .legend-text {{
                                        display: none; /* Oculta a legenda no modo mobile */
                                    }}

                                    .arrow {{
                                        display: none; /* Oculta a seta no modo mobile */
                                    }}
                                    .table-container {{
                                        width: 100%;
                                        max-height: 450px; /* Define uma altura máxima para a tabela */
                                    }}
                                    .table-container th:nth-child(11), .table-container td:nth-child(11) {{
                                        width: 120px; /* Define uma largura menor para a coluna "Ações" */
                                        text-align: center; /* Centraliza o texto e os botões na coluna */
                                    }}
                                    .table-container td {{
                                        padding: 4px; /* Diminui a altura dos td */
                                        text-align: left;
                                        border-bottom: 1px solid #ddd;
                                        vertical-align: middle; /* Garante que o conteúdo fique alinhado verticalmente */
                                        white-space: nowrap; /* Impede quebra de linha em células */
                                        overflow: hidden; /* Oculta conteúdo que ultrapassa o limite */
                                        text-overflow: ellipsis; /* Adiciona reticências ao conteúdo excedente */
                                    }}
                                    .table-container th {{
                                        background-color: #f2f2f2;
                                        position: sticky;
                                        top: 0;
                                        z-index: 1;
                                        text-align: center; /* Centraliza o texto do thead */
                                    }}
                                    .table-container {{
                                        font-size: 0.9em;
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
                                    .btn-group {{
                                        display: flex;
                                        justify-content: center;
                                        margin-top: 20px;
                                    }}
                                    .btn-approve-table, .btn-reject-table {{
                                        display: inline-block;
                                        width: 90px;
                                        margin-right: 5px; /* Adiciona espaçamento entre os botões */
                                        text-align: center; /* Centraliza o texto do botão */
                                    }}
                                    .btn-approve-table {{
                                        background-color: #28a745;
                                        color: white;
                                        margin-bottom: 5px; /* Adiciona espaçamento vertical entre os botões */
                                    }}
                                    .btn-reject-table {{
                                        background-color: #dc3545;
                                        color: white;
                                        margin-top: 5px;
                                    }}
                                    .btn-approve-table.disabled, .btn-reject-table.disabled {{
                                        visibility: hidden; /* Torna os botões invisíveis quando desabilitados */
                                    }}
                                    .btn-relatorio:hover {{
                                        background-color: #63B8FF; /* Azul claro ao passar o mouse */
                                    }}
                                    @media (max-width: 768px) {{
                                        .filters-container {{
                                            display: flex;
                                            flex-direction: column;
                                            align-items: stretch;
                                            width: 100%;
                                        }}
                                        .toggle-filters {{
                                            background-color: #1E90FF;
                                            color: white;
                                            padding: 10px;
                                            text-align: center;
                                            border: none;
                                            border-radius: 5px;
                                            margin: 10px 0;
                                            width: 80%;
                                            max-width: 130px;
                                            align-self: center;
                                        }}
                                        #time_entries_form {{
                                            display: flex;
                                            flex-direction: column;
                                            gap: 10px;
                                            width: 100%;
                                        }}
                                        #filter-fields {{
                                            display: flex;
                                            flex-direction: column;
                                            gap: 10px;
                                        }}
                                        .filters label {{
                                            font-weight: bold;
                                            margin-bottom: 5px;
                                        }}
                                        .filters input, .filters select {{
                                            width: 100%;
                                            padding: 10px;
                                            border: 1px solid #ddd;
                                            border-radius: 5px;
                                        }}
                                        .legend-text {{
                                            display: none; /* Oculta a legenda no modo mobile */
                                        }}
                                        .arrow {{
                                            display: none; /* Oculta a seta no modo mobile */
                                        }}
                                        .container {{
                                            padding: 10px;
                                            overflow-y: auto;
                                            max-height: 80vh;
                                        }}
                                        .header-logo h1 {{
                                            font-size: 1.5em;
                                        }}
                                        .filters {{
                                            display: flex;
                                            align-items: center;
                                            gap: 10px;
                                            margin: 0; /* Remove margem */
                                            padding: 0; /* Remove padding */
                                        }}
                                        .table-wrapper {{
                                            overflow-x: auto;
                                        }}
                                        .table-container {{
                                            font-size: 0.9em;
                                            overflow-x: scroll;
                                        }}
                                        .btn-group {{
                                            flex-direction: column;
                                            align-items: center;
                                        }}
                                        .btn-group .btn-relatorio {{
                                            width: 180px; /* Ocupa a largura total do contêiner no modo mobile */
                                            height: 40px; /* Garante que a altura do botão seja mantida */
                                            margin: 0px 0;
                                        }}
                                        #hours-summary {{
                                            display: block; /* Mostrar no modo mobile */
                                        }}
                                    }}
                                    @media (min-width: 769px) {{
                                        .toggle-filters {{
                                            display: none;
                                        }}
                                        #time_entries_form {{
                                            display: block !important;
                                        }}
                                        #hours-summary {{
                                            display: none; /* Esconder no modo desktop */
                                        }}
                                        .legend-text {{
                                            display: block; /* Mostrar a legenda no modo desktop */
                                        }}
                                        .arrow {{
                                            display: inline; /* Mostrar a seta no modo desktop */
                                        }}
                                    }}
                                    .filters label, .legend-button {{
                                        color: black;
                                    }}
                                    table {{
                                        width: 100%;
                                    }}
                                    #detailsPopup {{
                                        display: none;
                                        position: fixed;
                                        top: 50%;
                                        left: 50%;
                                        transform: translate(-50%, -50%);
                                        background-color: white;
                                        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3);
                                        z-index: 1000;
                                        padding: 20px;
                                        border-radius: 5px;
                                        max-width: 90%;
                                        max-height: 90%;
                                        overflow-y: auto;
                                    }}
                                    #detailsPopup .btn-group {{
                                        display: flex;
                                        justify-content: space-between;
                                        margin-top: 20px;
                                    }}
                                    .close-button {{
                                        position: absolute;
                                        top: 10px;
                                        right: 10px;
                                        background: none;
                                        border: none;
                                        font-size: 1.5rem;
                                        cursor: pointer;
                                    }}
                                    .close-button:hover {{
                                        color: red;
                                    }}
                                    @media (max-width: 768px) {{
                                        #all-actions {{
                                            display: none;
                                        }}
                                        #hours-summary-table {{
                                            display: none;
                                        }}
                                        .mobile-actions {{
                                            display: block;
                                        }}
                                        #hours-summary {{
                                            display: block;
                                        }}
                                        .hours-summary {{
                                            font-size: 1.2em;
                                            font-weight: bold;
                                            color: #333;
                                            margin-top: 10px;
                                        }}
                                        .hours-summary p {{
                                            margin: 5px 0;
                                        }}
                                        .hours-total-mobile, .hours-approved-mobile, .hours-unapproved-mobile {{
                                            color: #1E90FF;
                                        }}
                                        .hours-approved-mobile {{
                                            color: #28a745;
                                        }}
                                        .hours-repproved-mobile {{
                                            color: #dc3545;
                                        }}
                                        .hours-unapproved-mobile {{
                                            color: #bbdb03;
                                        }}
                                    }}
                                    @media (min-width: 769px) {{
                                        #mobile-actions-buttons {{
                                            display: none; /* Tornar invisível no modo desktop */
                                        }}
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
                                    <div id="hours-summary" class="hours-summary">
                                        <p>Total de Horas: <span class="hours-total-mobile">0</span></p>
                                        <p>Horas Aprovadas: <span class="hours-approved-mobile">0</span></p>
                                        <p>Horas Reprovadas: <span class="hours-repproved-mobile">0</span></p>
                                        <p>Horas Pendentes: <span class="hours-unapproved-mobile">0</span></p>
                                    </div>
                                    <div id="mobile-actions-buttons" class="mobile-actions">
                                        <div class="btn-group">
                                            <button type="button" onclick="approveAll('{token}', '{approve_entry_ids}', {is_client})" class="btn btn-approve">Aprovar Todos</button>
                                            <button type="button" onclick="rejectAll('{token}', '{reject_entry_ids}', {is_client})" class="btn btn-reject">Reprovar Todos</button>
                                        </div>
                                    </div>
                                    <div class="filters-container">
                                        <button class="toggle-filters" onclick="toggleFilters()">Filtros</button>
                                        <form id="time_entries_form" method="get" action="https://timesheetqas.evtit.com/validar_selecionados?client={is_client}">
                                            <fieldset class="collapsible" style="border: none;">
                                                <legend class="legend-text" onclick="toggleFieldset(this);">
                                                    <span class="legend-button">
                                                        <span class="arrow">▶</span>
                                                        Filtros
                                                    </span>
                                                </legend>
                                                <div id="filter-fields" class="filter-fields-style" style="display: block;">
                                                    <label for="filterInput">Buscar:</label>
                                                    <input type="text" id="filterInput" onkeyup="filterBySelect()" placeholder="Digite para buscar...">
                                                    <label for="userSelect">Usuário:</label>
                                                    <select id="userSelect" onchange="filterBySelect()">
                                                        <option value="ALL">Todos</option>
                                                        {''.join(
                [f'<option value="{usuario.upper()}">{usuario}</option>' for usuario in sorted(usuarios)])}
                                                    </select>
                                                    <label for="projectSelect">Projeto:</label>
                                                    <select id="projectSelect" onchange="filterBySelect()">
                                                        <option value="ALL">Todos</option>
                                                        {''.join(
                [f'<option value="{projeto.upper()}">{projeto}</option>' for projeto in sorted(projetos)])}
                                                    </select>
                                                    <label for="approvalSelect">Aprovado:</label>
                                                    <select id="approvalSelect" onchange="filterBySelect()">
                                                        <option value="ALL">Todos</option>
                                                        <option value="SIM">Aprovadas</option>
                                                        <option value="NÃO">Reprovadas</option>
                                                        <option value="PENDENTE">Pendentes</option>
                                                    </select>
                                                </div>
                                            </fieldset>
                                        </form>
                                    </div>
                                    <div class="table-container">
                                        {table_html}
                                        <div id="all-actions" class="btn-group">
                                            <button type="button" onclick="approveAll('{token}', '{approve_entry_ids}', {is_client})" class="btn btn-approve">Aprovar Todos</button>
                                            <button type="button" onclick="rejectAll('{token}', '{reject_entry_ids}', {is_client})" class="btn btn-reject">Reprovar Todos</button>
                                            <button type="button" onclick="sendFilteredData()" class="btn-relatorio">Enviar Relatório - Cliente</button>
                                        </div>
                                        <div id="selected-actions" class="btn-group">
                                            <button type="button" id="approve-selected" class="btn btn-approve" data-action="aprovar">Aprovar Selecionados</button>
                                            <button type="button" id="reject-selected" class="btn btn-reject" data-action="reprovar">Reprovar Selecionados</button>
                                            <button type="button" onclick="sendFilteredData()" class="btn-relatorio">Enviar Relatório Selecionados - Cliente</button>

                                        </div>
                                    </div>
                                </div>
                                <div id="detailsPopup">
                                    <div id="popupContent"></div>
                                    <button type="button" class="close-button" onclick="hideDetailsPopup()">×</button>
                                </div>
                                <script>
                                    document.addEventListener('DOMContentLoaded', function() {{
                                        const projectSelect = document.getElementById('projectSelect');
                                        if (projectSelect && project_name) {{
                                            const options = projectSelect.options;
                                            for (let i = 0; i < options.length; i++) {{
                                                if (options[i].text === project_name) {{
                                                    projectSelect.selectedIndex = i;
                                                    break;
                                                }}
                                            }}
                                        }}

                                        document.getElementById("filterInput").addEventListener("keyup", function() {{
                                            filterBySelect();
                                        }});

                                        document.getElementById("userSelect").addEventListener("change", function() {{
                                            filterBySelect();
                                        }});

                                        document.getElementById("projectSelect").addEventListener("change", function() {{
                                            filterBySelect();
                                        }});

                                        document.getElementById("approvalSelect").addEventListener("change", function() {{
                                            filterBySelect();
                                        }});

                                        const tableRows = document.querySelectorAll('#time_entries_table tbody tr');

                                        tableRows.forEach(row => {{
                                            row.addEventListener('click', function() {{
                                             if (window.innerWidth <= 768) {{
                                                var entryData = {{
                                                    spent_on: row.cells[1].textContent.trim(),
                                                    user: {{ name: row.cells[2].textContent.trim() }},
                                                    activity: {{ name: row.cells[3].textContent.trim() }},
                                                    project: {{ name: row.cells[4].textContent.trim() }},
                                                    comments: row.cells[5].textContent.trim(),
                                                    custom_fields: [
                                                        {{ name: 'Hora inicial (HH:MM)', value: row.cells[6].textContent.trim() }},
                                                        {{ name: 'Hora final (HH:MM)', value: row.cells[7].textContent.trim() }},
                                                        {{ name: 'Local de trabalho', value: 'Indisponível' }},
                                                        {{ name: 'TS - Aprovado - CLI', value: row.cells[9].textContent.trim() }}
                                                    ],
                                                    hours: row.cells[8].textContent.trim(),
                                                    id: row.id.split('-')[2]
                                                }};
                                                if (entryData) {{
                                                    var entry = entryData;

                                                    var popup = document.getElementById('detailsPopup');
                                                    var content = document.getElementById('popupContent');

                                                    var horaInicial = entry.custom_fields.find(field => field.name === 'Hora inicial (HH:MM)').value;
                                                    var horaFinal = entry.custom_fields.find(field => field.name === 'Hora final (HH:MM)').value;
                                                    var localTrabalho = entry.custom_fields.find(field => field.name === 'Local de trabalho').value;
                                                    var aprovado = entry.custom_fields.find(field => field.name === 'TS - Aprovado - CLI').value;
                                                    var approved_value = (aprovado === '1') ? 'Sim' : (aprovado === '0') ? 'Não' : 'Pendente';

                                                    content.innerHTML = `
                                                        <p><strong>Data:</strong> ${{entry['spent_on']}}</p>
                                                        <p><strong>Usuário:</strong> ${{entry['user']['name']}}</p>
                                                        <p><strong>Atividade:</strong> ${{entry['activity']['name']}}</p>
                                                        <p><strong>Projeto:</strong> ${{entry['project']['name']}}</p>
                                                        <p><strong>Comentários:</strong> ${{entry['comments']}}</p>
                                                        <p><strong>Hora Inicial:</strong> ${{horaInicial}}</p>
                                                        <p><strong>Hora Final:</strong> ${{horaFinal}}</p>
                                                        <p><strong>Total de Horas:</strong> ${{entry['hours']}}</p>
                                                        <p><strong>Aprovado:</strong> ${{aprovado}}</p>
                                                        <div class="btn-group">
                                                            <a href="#" onclick="approveHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{aprovado}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-approve-table ${{aprovado === 'Sim' ? 'disabled' : ''}}" style="opacity:${{aprovado === 'Sim' ? '0' : '1'}};">Aprovar</a>
                                                            <a href="#" onclick="rejectHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{aprovado}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-reject-table ${{aprovado === 'Sim' ? 'disabled' : ''}}" style="opacity:${{aprovado === 'Sim' ? '0' : '1'}};">Reprovar</a>
                                                        </div>
                                                    `;
                                                    popup.style.display = 'block';
                                                }} else {{
                                                    console.error('Dados da entrada não encontrados.');
                                                }}
                                                }}
                                            }});
                                        }});
                                    }});

                                    function filterTable() {{
                                        filterBySelect();
                                    }}
                                    
                                    function filterBySelect() {{
                                        var userSelect = document.getElementById("userSelect").value.toUpperCase();
                                        var projectSelect = document.getElementById("projectSelect").value.toUpperCase();
                                        var approvalSelect = document.getElementById("approvalSelect").value.toUpperCase();
                                        var table = document.getElementById("time_entries_table");
                                        var tr = table.getElementsByTagName("tr");

                                        let totalHours = 0;
                                        let approvedHours = 0;
                                        let repprovedHours = 0;
                                        let unapprovedHours = 0;

                                        let filteredApproveIds = [];
                                        let filteredRejectIds = [];

                                        for (var i = 1; i < tr.length; i++) {{
                                            tr[i].style.display = "none";
                                            var userTd = tr[i].getElementsByTagName("td")[2];
                                            var projectTd = tr[i].getElementsByTagName("td")[4];
                                            var approvalTd = tr[i].getElementsByTagName("td")[9];
                                            if (userTd && projectTd && approvalTd) {{
                                                var userValue = userTd.textContent || userTd.innerText;
                                                var projectValue = projectTd.textContent || projectTd.innerText;
                                                var approvalValue = approvalTd.textContent || approvalTd.innerText;
                                                if ((userSelect === "ALL" || userValue.toUpperCase() === userSelect) &&
                                                    (projectSelect === "ALL" || projectValue.toUpperCase() === projectSelect) &&
                                                    (approvalSelect === "ALL" || approvalValue.toUpperCase() === approvalSelect)) {{
                                                    tr[i].style.display = "";
                                                    var entryId = tr[i].getElementsByTagName("td")[0].querySelector("input").value;
                                                    var entryHours = parseFloat(tr[i].getElementsByTagName("td")[8].textContent);
                                                    totalHours += entryHours;
                                                    if (approvalValue === 'Sim') {{
                                                        approvedHours += entryHours;

                                                    }} else if (approvalValue === 'Não') {{
                                                        repprovedHours += entryHours;
                                                        filteredApproveIds.push(entryId);

                                                    }} else if (approvalValue === 'Pendente') {{
                                                        unapprovedHours += entryHours;
                                                        filteredApproveIds.push(entryId);
                                                        filteredRejectIds.push(entryId);
                                                    }}
                                                }}
                                            }}
                                        }}

                                        document.querySelector('.hours-total').textContent = totalHours.toFixed(1);
                                        document.querySelector('.hours-approved').textContent = approvedHours.toFixed(1);
                                        document.querySelector('.hours-repproved').textContent = repprovedHours.toFixed(1);
                                        document.querySelector('.hours-unapproved').textContent = unapprovedHours.toFixed(1);

                                        // Atualiza os botões no modo desktop
                                        document.querySelector('.btn-approve').setAttribute('onclick', `approveAll('{token}', '${{filteredApproveIds.join(',')}}', {is_client})`);
                                        document.querySelector('.btn-reject').setAttribute('onclick', `rejectAll('{token}', '${{filteredRejectIds.join(',')}}', {is_client})`);

                                        // Atualiza os botões no modo mobile
                                        document.querySelector('.mobile-actions .btn-approve').setAttribute('onclick', `approveAll('{token}', '${{filteredApproveIds.join(',')}}', {is_client})`);
                                        document.querySelector('.mobile-actions .btn-reject').setAttribute('onclick', `rejectAll('{token}', '${{filteredRejectIds.join(',')}}', {is_client})`);

                                        // Update mobile summary
                                        updateMobileSummary();
                                    }}

                                    function toggleAll(source) {{
                                        checkboxes = document.getElementsByName('selected_entries');
                                        for(var i=0, n=checkboxes.length;i<n;i++) {{
                                            if (!checkboxes[i].disabled) {{
                                                checkboxes[i].checked = source.checked;
                                            }}
                                        }}
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
                                            showAlert('Relatório enviado com sucesso', 'success');
                                        }})
                                        .catch((error) => {{
                                            showAlert('Erro ao enviar o relatório: ' + error, 'error');
                                        }});
                                    }}

                                    function showAlert(message, type) {{
                                        var alertDiv = document.createElement('div');
                                        alertDiv.className = `alert alert-${type}`;
                                        alertDiv.textContent = message;

                                        // Estilização básica para o popup
                                        alertDiv.style.position = 'fixed';
                                        alertDiv.style.top = '20px';
                                        alertDiv.style.left = '50%';
                                        alertDiv.style.transform = 'translateX(-50%)';
                                        alertDiv.style.padding = '10px';
                                        alertDiv.style.zIndex = 1000;
                                        alertDiv.style.backgroundColor = type === 'success' ? 'green' : 'red';
                                        alertDiv.style.color = 'white';
                                        alertDiv.style.borderRadius = '5px';
                                        alertDiv.style.boxShadow = '0 0 10px rgba(0, 0, 0, 0.1)';
                                        alertDiv.style.fontSize = '16px';

                                        document.body.appendChild(alertDiv);

                                        // Remover o popup após 3 segundos
                                        setTimeout(() => {{
                                            document.body.removeChild(alertDiv);
                                        }}, 3000);
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
                                                    id: td[0] && td[0].querySelector("input") ? td[0].querySelector("input").value : "N/A",
                                                    date: td[1] ? td[1].textContent : "N/A",
                                                    user: td[2] ? td[2].textContent : "N/A",
                                                    activity: td[3] ? td[3].textContent : "N/A",
                                                    project: td[4] ? td[4].textContent : "N/A",
                                                    comments: td[5] ? td[5].textContent : "N/A",
                                                    start_time: td[6] ? td[6].textContent : "N/A",
                                                    end_time: td[7] ? td[7].textContent : "N/A",
                                                    hours: td[8] ? td[8].textContent : "N/A"
                                                }};

                                                data.push(entry);
                                            }}
                                        }} else {{
                                            for (var i = 1; i < tr.length; i++) {{
                                                if (tr[i].style.display !== "none") {{
                                                    var td = tr[i].getElementsByTagName("td");

                                                    var entry = {{
                                                        id: td[0] && td[0].querySelector("input") ? td[0].querySelector("input").value : "N/A",
                                                        date: td[1] ? td[1].textContent : "N/A",
                                                        user: td[2] ? td[2].textContent : "N/A",
                                                        activity: td[3] ? td[3].textContent : "N/A",
                                                        project: td[4] ? td[4].textContent : "N/A",
                                                        comments: td[5] ? td[5].textContent : "N/A",
                                                        start_time: td[6] ? td[6].textContent : "N/A",
                                                        end_time: td[7] ? td[7].textContent : "N/A",
                                                        hours: td[8] ? td[8].textContent : "N/A"
                                                    }};

                                                    data.push(entry);
                                                }}
                                            }}
                                        }}

                                        return data;
                                    }}

                                    function approveAll(token, entryIds, isClient) {{
                                        fetch("{API_URL}aprovar_todos?token=" + token + "&entries=" + entryIds + "&client=" + isClient)
                                        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
                                        .then(result => {{
                                            const status = result.status;
                                            const body = result.body;
                                            showAlert(body.message, status === 200 ? 'success' : 'error');
                                            if (status === 200) {{
                                                location.reload();
                                            }}
                                        }})
                                        .catch(error => {{
                                            console.error('Erro:', error);
                                            showAlert('Erro ao aprovar horas.', 'error');
                                        }});
                                    }}

                                    function rejectAll(token, entryIds, isClient) {{
                                        fetch("{API_URL}reprovar_todos?token=" + token + "&entries=" + entryIds + "&client=" + isClient)
                                        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
                                        .then(result => {{
                                            const status = result.status;
                                            const body = result.body;
                                            showAlert(body.message, status === 200 ? 'success' : 'error');
                                            if (status === 200) {{
                                                location.reload();
                                            }}
                                        }})
                                        .catch(error => {{
                                            console.error('Erro:', error);
                                            showAlert('Erro ao reprovar horas.', 'error');
                                        }});
                                    }}

                                    function updateRowsApproval(entryIds, isApproved) {{
                                        var table = document.getElementById("time_entries_table");
                                        var tr = table.getElementsByTagName("tr");

                                        let totalHours = 0;
                                        let approvedHours = 0;
                                        let repprovedHours = 0;
                                        let pendingHours = 0;

                                        for (var i = 1; i < tr.length; i++) {{
                                            var row = tr[i];
                                            var entryId = row.getElementsByTagName("td")[0].querySelector("input").value;
                                            var td = row.getElementsByTagName("td");
                                            var entryHours = parseFloat(td[8].textContent);
                                            var approvalValue = td[9].textContent;

                                            if (entryIds.includes(entryId)) {{
                                                if (isApproved && approvalValue !== "Sim") {{
                                                    td[9].textContent = "Sim";
                                                    approvedHours += entryHours;
                                                    if (approvalValue === "Não") {{
                                                        repprovedHours -= entryHours;
                                                    }} else if (approvalValue === "Pendente") {{
                                                        pendingHours -= entryHours;
                                                    }}
                                                }} else if (!isApproved && approvalValue !== "Não") {{
                                                    td[9].textContent = "Não";
                                                    repprovedHours += entryHours;
                                                    if (approvalValue === "Sim") {{
                                                        approvedHours -= entryHours;
                                                    }} else if (approvalValue === "Pendente") {{
                                                        pendingHours -= entryHours;
                                                    }}
                                                }}
                                                disableRow(entryId);
                                            }} else {{
                                                if (approvalValue === "Sim") {{
                                                    approvedHours += entryHours;
                                                }} else if (approvalValue === "Não") {{
                                                    repprovedHours += entryHours;
                                                }} else if (approvalValue === "Pendente") {{
                                                    pendingHours += entryHours;
                                                }}
                                            }}
                                            totalHours += entryHours;
                                        }}

                                        document.querySelector('.hours-total').textContent = totalHours.toFixed(1);
                                        document.querySelector('.hours-approved').textContent = approvedHours.toFixed(1);
                                        document.querySelector('.hours-repproved').textContent = repprovedHours.toFixed(1);
                                        document.querySelector('.hours-unapproved').textContent = pendingHours.toFixed(1);

                                        // Update mobile summary
                                        updateMobileSummary();
                                    }}

                                    function disableRow(entryId) {{
                                        var row = document.getElementById("entry-row-" + entryId);
                                        var checkBox = row.querySelector('input[type="checkbox"]');
                                        var approveButton = row.querySelector('.btn-approve-table');
                                        var rejectButton = row.querySelector('.btn-reject-table');

                                        if (checkBox) {{
                                            checkBox.disabled = true;
                                        }}
                                        if (approveButton) {{
                                            approveButton.classList.add('disabled');
                                        }}
                                        if (rejectButton) {{
                                            rejectButton.classList.add('disabled');
                                        }}
                                    }}

                                    function showDetailsPopup(entry) {{
                                        var popup = document.getElementById('detailsPopup');
                                        var content = document.getElementById('popupContent');
                                        var horaInicial = entry.custom_fields.find(field => field.name === 'Hora inicial (HH:MM)').value;
                                        var horaFinal = entry.custom_fields.find(field => field.name === 'Hora final (HH:MM)').value;
                                        var localTrabalho = entry.custom_fields.find(field => field.name === 'Local de trabalho').value;
                                        var aprovado = entry.custom_fields.find(field => field.name === 'TS - Aprovado - CLI').value;
                                        var approved_value = (aprovado === 'Sim') ? 'Sim' : (aprovado === 'Não') ? 'Não' : 'Pendente';

                                        content.innerHTML = `
                                            <p><strong>Data:</strong> ${{entry['spent_on']}}</p>
                                            <p><strong>Usuário:</strong> ${{entry['user']['name']}}</p>
                                            <p><strong>Atividade:</strong> ${{entry['activity']['name']}}</p>
                                            <p><strong>Projeto:</strong> ${{entry['project']['name']}}</p>
                                            <p><strong>Comentários:</strong> ${{entry['comments']}}</p>
                                            <p><strong>Hora Inicial:</strong> ${{horaInicial}}</p>
                                            <p><strong>Hora Final:</strong> ${{horaFinal}}</p>
                                            <p><strong>Total de Horas:</strong> ${{entry['hours']}}</p>
                                            <p><strong>Aprovado:</strong> ${{approved_value}}</p>
                                            <div class="btn-group">
                                                <a href="#" onclick="approveHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-approve-table ${{approved_value === 'Sim' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Sim' ? '0' : '1'}};">Aprovar</a>
                                                <a href="#" onclick="rejectHour(${{entry['id']}}, '{request.args.get('token')}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-reject-table ${{approved_value === 'Não' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Não' ? '0' : '1'}};">Reprovar</a>
                                            </div>
                                        `;
                                        popup.style.display = 'block';
                                    }}

                                    function hideDetailsPopup() {{
                                        var popup = document.getElementById('detailsPopup');
                                        popup.style.display = 'none';
                                    }}

                                    function updateMobileSummary() {{
                                        document.querySelector('.hours-total-mobile').textContent = document.querySelector('.hours-total').textContent;
                                        document.querySelector('.hours-approved-mobile').textContent = document.querySelector('.hours-approved').textContent;
                                        document.querySelector('.hours-repproved-mobile').textContent = document.querySelector('.hours-repproved').textContent;
                                        document.querySelector('.hours-unapproved-mobile').textContent = document.querySelector('.hours-unapproved').textContent;
                                    }}

                                    // Ensure initial values are set for mobile view
                                    document.addEventListener('DOMContentLoaded', function() {{
                                        updateMobileSummary();
                                    }});
                                    function toggleFilters() {{
                                        var form = document.getElementById("time_entries_form");
                                                        var xpath = "//*[@id='filter-fields']";
                                                        var result = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
                                                        var filterFields = result.singleNodeValue;
                            
                                                        if (form.style.display === "none" || form.style.display === "") {{
                                                            form.style.display = "block";
                                                            filterFields.style.display = "block";  // Certifique-se de que os campos de filtro também estejam visíveis
                                                        }} else {{
                                                            form.style.display = "none";
                                                            filterFields.style.display = "none";  // Certifique-se de que os campos de filtro também estejam escondidos
                                                        }}
                                    }}
                                </script>
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


@app.route('/relatorio_horas', methods=['GET'])
def relatorio_horas_geral():
    try:
        # Define o período de 30 dias
        today = datetime.today()
        first_day_of_month = today.replace(day=1)
        last_day_of_month = today.replace(day=calendar.monthrange(today.year, today.month)[1])
        start_date = first_day_of_month.strftime('%Y-%m-%d')
        end_date = last_day_of_month.strftime('%Y-%m-%d')

        # Obtém o número da página da requisição
        page = int(request.args.get('page', 1))
        limit = 100

        # Faz uma requisição para obter as entradas de tempo do Redmine
        url = f'{REDMINE_URL}/time_entries.json?limit={limit}&offset={(page - 1) * limit}&from={start_date}&to={end_date}'
        entries_response = requests.get(url, headers={
            'X-Redmine-API-Key': REDMINE_API_KEY,
            'Content-Type': 'application/json'
        }, verify=False)

        if entries_response.ok:
            # Filtra as entradas de tempo para incluir apenas aquelas que não foram aprovadas
            time_entries = entries_response.json().get('time_entries', [])
            unapproved_entries = [entry for entry in time_entries if any(
                field['name'] == 'TS - Aprovado - EVT' and (field['value'] == '0' or field['value'] == '') for field in
                entry.get('custom_fields', []))]
            entry_ids = ','.join([str(entry['id']) for entry in unapproved_entries])
            table_html = create_html_table(time_entries)
            # Obtém o token da URL atual
            user = get_current_user()
            user_id = user['user']['id']
            token = get_or_create_token(user_id, user['user']['mail'])
            # Constrói a lista de IDs das entradas
            project_name = request.args.get('project')
            is_client = 1 if 'client' in request.full_path else 0
            # Extrai usuários e projetos para os filtros
            usuarios = {entry['user']['name'] for entry in time_entries}
            projetos = {entry['project']['name'] for entry in time_entries}
            # Constrói a lista de IDs das entradas
            approve_entry_ids = ','.join(
                [str(entry['id']) for entry in unapproved_entries if
                 any(field['name'] == 'TS - Aprovado - EVT' and (field['value'] == '0' or field['value'] == '') for
                     field in entry.get('custom_fields', []))]
            )
            reject_entry_ids = ','.join(
                [str(entry['id']) for entry in unapproved_entries if
                 any(field['name'] == 'TS - Aprovado - EVT' and field['value'] == '1' for field in
                     entry.get('custom_fields', []))]
            )

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
                    function toggleFieldset(legend) {{
                        var fieldset = legend.parentElement;
                        var isCollapsed = fieldset.classList.toggle('collapsed');
                        var div = fieldset.querySelector('div');
                        var arrow = legend.querySelector('.arrow');
                        if (isCollapsed) {{
                            div.style.display = 'none';
                            arrow.innerHTML = '▼';  // Seta para a direita
                        }} else {{
                            div.style.display = 'block';
                            arrow.innerHTML = '▶';  // Seta para baixo
                        }}
                    }}

                    function toggleFilters() {{
                        var filters = document.getElementById('filter-fields');
                        if (filters.style.display === 'none') {{
                            filters.style.display = 'block';
                        }} else {{
                            filters.style.display = 'none';
                        }}
                    }}

                    document.addEventListener('DOMContentLoaded', function() {{
                         const usuarios = {json.dumps(list(usuarios))};
                        const projetos = {json.dumps(list(projetos))};
                        
                        // Preencher o select de usuários
                        const userSelect = document.getElementById('userSelect');
                        if (userSelect) {{
                            userSelect.innerHTML = '<option value="ALL">Todos</option>';
                            usuarios.forEach(usuario => {{
                                userSelect.innerHTML += `<option value="${{usuario}}">${{usuario}}</option>`;
                            }});
                        }}
            
                        // Preencher o select de projetos
                        const projectSelect = document.getElementById('projectSelect');
                        if (projectSelect) {{
                            projectSelect.innerHTML = '<option value="ALL">Todos</option>';
                            projetos.forEach(projeto => {{
                                projectSelect.innerHTML += `<option value="${{projeto}}">${{projeto}}</option>`;
                            }});
                        }}
                        
                        // Seleciona o projeto atual, se houver
                        const project_name = "{project_name}";
                        if (projectSelect && project_name) {{
                            const options = projectSelect.options;
                            for (let i = 0; i < options.length; i++) {{
                                if (options[i].text.toUpperCase() === project_name.toUpperCase()) {{
                                    projectSelect.selectedIndex = i;
                                    filterBySelect();
                                    break;
                                }}
                            }}
                        }}

                        function createTableHtml(timeEntries) {{
                            let tableHtml = '<thead><tr><th>Data</th><th>Usuário</th><th>Atividade</th><th>Projeto</th><th>Comentários</th><th>Hora Inicial</th><th>Hora Final</th><th>Horas</th><th>Aprovado</th></tr></thead><tbody>';
                            timeEntries.forEach(entry => {{
                                tableHtml += `<tr>
                                                <td>${{entry.spent_on}}</td>
                                                <td>${{entry.user.name}}</td>
                                                <td>${{entry.activity.name}}</td>
                                                <td>${{entry.project.name}}</td>
                                                <td>${{entry.comments}}</td>
                                                <td>${{entry.custom_fields.find(field => field.name === 'Hora inicial (HH:MM)').value}}</td>
                                                <td>${{entry.custom_fields.find(field => field.name === 'Hora final (HH:MM)').value}}</td>
                                                <td>${{entry.hours}}</td>
                                                <td>${{entry.custom_fields.find(field => field.name === 'TS - Aprovado - CLI').value}}</td>
                                            </tr>`;
                            }});
                            tableHtml += '</tbody>';
                            return tableHtml;
                        }}

                        document.getElementById("filterInput").addEventListener("keyup", function() {{
                            filterBySelect();
                        }});

                        document.getElementById("userSelect").addEventListener("change", function() {{
                            filterBySelect();
                        }});

                        document.getElementById("projectSelect").addEventListener("change", function() {{
                            filterBySelect();
                        }});

                        document.getElementById("approvalSelect").addEventListener("change", function() {{
                            filterBySelect();
                        }});

                        const tableRows = document.querySelectorAll('#time_entries_table tbody tr');

                        tableRows.forEach(row => {{
                            row.addEventListener('click', function() {{
                             if (window.innerWidth <= 768) {{
                                var entryData = {{
                                    spent_on: row.cells[1].textContent.trim(),
                                    user: {{ name: row.cells[2].textContent.trim() }},
                                    activity: {{ name: row.cells[3].textContent.trim() }},
                                    project: {{ name: row.cells[4].textContent.trim() }},
                                    comments: row.cells[5].textContent.trim(),
                                    custom_fields: [
                                        {{ name: 'Hora inicial (HH:MM)', value: row.cells[6].textContent.trim() }},
                                        {{ name: 'Hora final (HH:MM)', value: row.cells[7].textContent.trim() }},
                                        {{ name: 'Local de trabalho', value: 'Indisponível' }},
                                        {{ name: 'TS - Aprovado - CLI', value: row.cells[9].textContent.trim() }}
                                    ],
                                    hours: row.cells[8].textContent.trim(),
                                    id: row.id.split('-')[2]
                                }};
                                if (entryData) {{
                                    var entry = entryData;

                                    var popup = document.getElementById('detailsPopup');
                                    var content = document.getElementById('popupContent');

                                    var horaInicial = entry.custom_fields.find(field => field.name === 'Hora inicial (HH:MM)').value;
                                    var horaFinal = entry.custom_fields.find(field => field.name === 'Hora final (HH:MM)').value;
                                    var localTrabalho = entry.custom_fields.find(field => field.name === 'Local de trabalho').value;
                                    var aprovado = entry.custom_fields.find(field => field.name === 'TS - Aprovado - CLI').value;
                                    var approved_value = (aprovado === '1') ? 'Sim' : (aprovado === '0') ? 'Não' : 'Pendente';

                                    content.innerHTML = `
                                        <p><strong>Data:</strong> ${{entry['spent_on']}}</p>
                                        <p><strong>Usuário:</strong> ${{entry['user']['name']}}</p>
                                        <p><strong>Atividade:</strong> ${{entry['activity']['name']}}</p>
                                        <p><strong>Projeto:</strong> ${{entry['project']['name']}}</p>
                                        <p><strong>Comentários:</strong> ${{entry['comments']}}</p>
                                        <p><strong>Hora Inicial:</strong> ${{horaInicial}}</p>
                                        <p><strong>Hora Final:</strong> ${{horaFinal}}</p>
                                        <p><strong>Total de Horas:</strong> ${{entry['hours']}}</p>
                                        <p><strong>Aprovado:</strong> ${{approved_value}}</p>
                                        <div class="btn-group">
                                            <a href="#" onclick="approveHour(${{entry['id']}}, '{{{{request.args.get('token')}}}}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-approve-table ${{approved_value === 'Sim' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Sim' ? '0' : '1'}};">Aprovar</a>
                                            <a href="#" onclick="rejectHour(${{entry['id']}}, '{{{{request.args.get('token')}}}}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-reject-table ${{approved_value === 'Sim' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Sim' ? '0' : '1'}};">Reprovar</a>
                                        </div>
                                    `;
                                    popup.style.display = 'block';
                                }} else {{
                                    console.error('Dados da entrada não encontrados.');
                                }}
                                }}
                            }});
                        }});
                    }});

                    function filterTable() {{
                        filterBySelect();
                    }}

                    function filterBySelect() {{
                        var userSelect = document.getElementById("userSelect").value.toUpperCase();
                        var projectSelect = document.getElementById("projectSelect").value.toUpperCase();
                        var approvalSelect = document.getElementById("approvalSelect").value.toUpperCase();
                        var table = document.getElementById("time_entries_table");
                        var tr = table.getElementsByTagName("tr");

                        let totalHours = 0;
                        let approvedHours = 0;
                        let repprovedHours = 0;
                        let unapprovedHours = 0;

                        let filteredApproveIds = [];
                        let filteredRejectIds = [];

                        for (var i = 1; i < tr.length; i++) {{
                            tr[i].style.display = "none";
                            var userTd = tr[i].getElementsByTagName("td")[2];
                            var projectTd = tr[i].getElementsByTagName("td")[4];
                            var approvalTd = tr[i].getElementsByTagName("td")[9];
                            if (userTd && projectTd && approvalTd) {{
                                var userValue = userTd.textContent || userTd.innerText;
                                var projectValue = projectTd.textContent || projectTd.innerText;
                                var approvalValue = approvalTd.textContent || approvalTd.innerText;
                                if ((userSelect === "ALL" || userValue.toUpperCase() === userSelect) &&
                                    (projectSelect === "ALL" || projectValue.toUpperCase() === projectSelect) &&
                                    (approvalSelect === "ALL" || approvalValue.toUpperCase() === approvalSelect)) {{
                                    tr[i].style.display = "";
                                    var entryId = tr[i].getElementsByTagName("td")[0].querySelector("input").value;
                                    var entryHours = parseFloat(tr[i].getElementsByTagName("td")[8].textContent);
                                    totalHours += entryHours;
                                    if (approvalValue === 'Sim') {{
                                        approvedHours += entryHours;

                                    }} else if (approvalValue === 'Não') {{
                                        repprovedHours += entryHours;
                                        filteredApproveIds.push(entryId);

                                    }} else if (approvalValue === 'Pendente') {{
                                        unapprovedHours += entryHours;
                                        filteredApproveIds.push(entryId);
                                        filteredRejectIds.push(entryId);
                                    }}
                                }}
                            }}
                        }}

                        document.querySelector('.hours-total').textContent = totalHours.toFixed(1);
                        document.querySelector('.hours-approved').textContent = approvedHours.toFixed(1);
                        document.querySelector('.hours-repproved').textContent = repprovedHours.toFixed(1);
                        document.querySelector('.hours-unapproved').textContent = unapprovedHours.toFixed(1);

                        // Atualiza os botões no modo desktop
                        document.querySelector('.btn-approve').setAttribute('onclick', `approveAll('{{token}}', '${{filteredApproveIds.join(',')}}', {is_client})`);
                        document.querySelector('.btn-reject').setAttribute('onclick', `rejectAll('{{token}}', '${{filteredRejectIds.join(',')}}', {is_client})`);

                        // Atualiza os botões no modo mobile
                        document.querySelector('.mobile-actions .btn-approve').setAttribute('onclick', `approveAll('{{token}}', '${{filteredApproveIds.join(',')}}', {is_client})`);
                        document.querySelector('.mobile-actions .btn-reject').setAttribute('onclick', `rejectAll('{{token}}', '${{filteredRejectIds.join(',')}}', {is_client})`);

                        // Update mobile summary
                        updateMobileSummary();
                    }}

                    function toggleAll(source) {{
                        checkboxes = document.getElementsByName('selected_entries');
                        for(var i=0, n=checkboxes.length;i<n;i++) {{
                            if (!checkboxes[i].disabled) {{
                                checkboxes[i].checked = source.checked;
                            }}
                        }}
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
                            showAlert('Relatório enviado com sucesso', 'success');
                        }})
                        .catch((error) => {{
                            showAlert('Erro ao enviar o relatório: ' + error, 'error');
                        }});
                    }}

                    function showAlert(message, type) {{
                        var alertDiv = document.createElement('div');
                        alertDiv.className = `alert alert-${{type}}`;
                        alertDiv.textContent = message;

                        // Estilização básica para o popup
                        alertDiv.style.position = 'fixed';
                        alertDiv.style.top = '20px';
                        alertDiv.style.left = '50%';
                        alertDiv.style.transform = 'translateX(-50%)';
                        alertDiv.style.padding = '10px';
                        alertDiv.style.zIndex = 1000;
                        alertDiv.style.backgroundColor = type === 'success' ? 'green' : 'red';
                        alertDiv.style.color = 'white';
                        alertDiv.style.borderRadius = '5px';
                        alertDiv.style.boxShadow = '0 0 10px rgba(0, 0, 0, 0.1)';
                        alertDiv.style.fontSize = '16px';

                        document.body.appendChild(alertDiv);

                        // Remover o popup após 3 segundos
                        setTimeout(() => {{
                            document.body.removeChild(alertDiv);
                        }}, 3000);
                    }}
                    function getQueryParam(param) {{
                        var urlParams = new URLSearchParams(window.location.search);
                        return urlParams.get(param);
                    }}
                    var current_page = parseInt(getQueryParam('page')) || 0;
                    
                     document.addEventListener('DOMContentLoaded', function() {{
                        // Chama as funções de filtro após carregar a página
                        filterBySelect();
                        // Adicione outras funções de filtro aqui, se houver
                    }});
                    function nextPage() {{
                        current_page += 1;
                        
                        const token = '{token}';
                        const nextPageUrl = `/relatorio_horas?page=${{current_page}}&token=${{token}}`;
                        window.location.href = nextPageUrl;
                    }}

                    function previousPage() {{
                        if (current_page > 1) {{
                            current_page -= 1;
                            const token = '{token}';
                            const previousPageUrl = `/relatorio_horas?page=${{current_page}}&token=${{token}}`;
                            window.location.href = previousPageUrl;
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
                                    id: td[0] && td[0].querySelector("input") ? td[0].querySelector("input").value : "N/A",
                                    date: td[1] ? td[1].textContent : "N/A",
                                    user: td[2] ? td[2].textContent : "N/A",
                                    activity: td[3] ? td[3].textContent : "N/A",
                                    project: td[4] ? td[4].textContent : "N/A",
                                    comments: td[5] ? td[5].textContent : "N/A",
                                    start_time: td[6] ? td[6].textContent : "N/A",
                                    end_time: td[7] ? td[7].textContent : "N/A",
                                    hours: td[8] ? td[8].textContent : "N/A"
                                }};

                                data.push(entry);
                            }}
                        }} else {{
                            for (var i = 1; i < tr.length; i++) {{
                                if (tr[i].style.display !== "none") {{
                                    var td = tr[i].getElementsByTagName("td");

                                    var entry = {{
                                        id: td[0] && td[0].querySelector("input") ? td[0].querySelector("input").value : "N/A",
                                        date: td[1] ? td[1].textContent : "N/A",
                                        user: td[2] ? td[2].textContent : "N/A",
                                        activity: td[3] ? td[3].textContent : "N/A",
                                        project: td[4] ? td[4].textContent : "N/A",
                                        comments: td[5] ? td[5].textContent : "N/A",
                                        start_time: td[6] ? td[6].textContent : "N/A",
                                        end_time: td[7] ? td[7].textContent : "N/A",
                                        hours: td[8] ? td[8].textContent : "N/A"
                                    }};

                                    data.push(entry);
                                }}
                            }}
                        }}

                        return data;
                    }}

                    function approveAll(token, entryIds, isClient) {{
                        fetch("{API_URL}aprovar_todos?token=" + token + "&entries=" + entryIds + "&client=" + isClient)
                        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
                        .then(result => {{
                            const status = result.status;
                            const body = result.body;
                            showAlert(body.message, status === 200 ? 'success' : 'error');
                            if (status === 200) {{
                                location.reload();
                            }}
                        }})
                        .catch(error => {{
                            console.error('Erro:', error);
                            showAlert('Erro ao aprovar horas.', 'error');
                        }});
                    }}

                    function rejectAll(token, entryIds, isClient) {{
                        fetch("{API_URL}reprovar_todos?token=" + token + "&entries=" + entryIds + "&client=" + isClient)
                        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
                        .then(result => {{
                            const status = result.status;
                            const body = result.body;
                            showAlert(body.message, status === 200 ? 'success' : 'error');
                            if (status === 200) {{
                                location.reload();
                            }}
                        }})
                        .catch(error => {{
                            console.error('Erro:', error);
                            showAlert('Erro ao reprovar horas.', 'error');
                        }});
                    }}

                    function updateRowsApproval(entryIds, isApproved) {{
                        var table = document.getElementById("time_entries_table");
                        var tr = table.getElementsByTagName("tr");

                        let totalHours = 0;
                        let approvedHours = 0;
                        let repprovedHours = 0;
                        let pendingHours = 0;

                        for (var i = 1; i < tr.length; i++) {{
                            var row = tr[i];
                            var entryId = row.getElementsByTagName("td")[0].querySelector("input").value;
                            var td = row.getElementsByTagName("td");
                            var entryHours = parseFloat(td[8].textContent);
                            var approvalValue = td[9].textContent;

                            if (entryIds.includes(entryId)) {{
                                if (isApproved && approvalValue !== "Sim") {{
                                    td[9].textContent = "Sim";
                                    approvedHours += entryHours;
                                    if (approvalValue === "Não") {{
                                        repprovedHours -= entryHours;
                                    }} else if (approvalValue === "Pendente") {{
                                        pendingHours -= entryHours;
                                    }}
                                }} else if (!isApproved && approvalValue !== "Não") {{
                                    td[9].textContent = "Não";
                                    repprovedHours += entryHours;
                                    if (approvalValue === "Sim") {{
                                        approvedHours -= entryHours;
                                    }} else if (approvalValue === "Pendente") {{
                                        pendingHours -= entryHours;
                                    }}
                                }}
                                disableRow(entryId);
                            }} else {{
                                if (approvalValue === "Sim") {{
                                    approvedHours += entryHours;
                                }} else if (approvalValue === "Não") {{
                                    repprovedHours += entryHours;
                                }} else if (approvalValue === "Pendente") {{
                                    pendingHours += entryHours;
                                }}
                            }}
                            totalHours += entryHours;
                        }}

                        document.querySelector('.hours-total').textContent = totalHours.toFixed(1);
                        document.querySelector('.hours-approved').textContent = approvedHours.toFixed(1);
                        document.querySelector('.hours-repproved').textContent = repprovedHours.toFixed(1);
                        document.querySelector('.hours-unapproved').textContent = pendingHours.toFixed(1);

                        // Update mobile summary
                        updateMobileSummary();
                    }}

                    function disableRow(entryId) {{
                        var row = document.getElementById("entry-row-" + entryId);
                        var checkBox = row.querySelector('input[type="checkbox"]');
                        var approveButton = row.querySelector('.btn-approve-table');
                        var rejectButton = row.querySelector('.btn-reject-table');

                        if (checkBox) {{
                            checkBox.disabled = true;
                        }}
                        if (approveButton) {{
                            approveButton.classList.add('disabled');
                        }}
                        if (rejectButton) {{
                            rejectButton.classList.add('disabled');
                        }}
                    }}

                    function showDetailsPopup(entry) {{
                        var popup = document.getElementById('detailsPopup');
                        var content = document.getElementById('popupContent');
                        var horaInicial = entry.custom_fields.find(field => field.name === 'Hora inicial (HH:MM)').value;
                        var horaFinal = entry.custom_fields.find(field => field.name === 'Hora final (HH:MM)').value;
                        var localTrabalho = entry.custom_fields.find(field => field.name === 'Local de trabalho').value;
                        var aprovado = entry.custom_fields.find(field => field.name === 'TS - Aprovado - CLI').value;
                        var approved_value = (aprovado === 'Sim') ? 'Sim' : (aprovado === 'Não') ? 'Não' : 'Pendente';

                        content.innerHTML = `
                            <p><strong>Data:</strong> ${{entry['spent_on']}}</p>
                            <p><strong>Usuário:</strong> ${{entry['user']['name']}}</p>
                            <p><strong>Atividade:</strong> ${{entry['activity']['name']}}</p>
                            <p><strong>Projeto:</strong> ${{entry['project']['name']}}</p>
                            <p><strong>Comentários:</strong> ${{entry['comments']}}</p>
                            <p><strong>Hora Inicial:</strong> ${{horaInicial}}</p>
                            <p><strong>Hora Final:</strong> ${{horaFinal}}</p>
                            <p><strong>Total de Horas:</strong> ${{entry['hours']}}</p>
                            <p><strong>Aprovado:</strong> ${{approved_value}}</p>
                            <div class="btn-group">
                                <a href="#" onclick="approveHour(${{entry['id']}}, '{{{{request.args.get('token')}}}}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-approve-table ${{approved_value === 'Sim' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Sim' ? '0' : '1'}};">Aprovar</a>
                                <a href="#" onclick="rejectHour(${{entry['id']}}, '{{{{request.args.get('token')}}}}', {is_client}, ${{entry['hours']}}, '${{approved_value}}'); setTimeout(() => location.reload(), 1000);" class="btn btn-reject-table ${{approved_value === 'Não' ? 'disabled' : ''}}" style="opacity:${{approved_value === 'Não' ? '0' : '1'}};">Reprovar</a>
                            </div>
                        `;
                        popup.style.display = 'block';
                    }}

                    function hideDetailsPopup() {{
                        var popup = document.getElementById('detailsPopup');
                        popup.style.display = 'none';
                    }}

                    function updateMobileSummary() {{
                        document.querySelector('.hours-total-mobile').textContent = document.querySelector('.hours-total').textContent;
                        document.querySelector('.hours-approved-mobile').textContent = document.querySelector('.hours-approved').textContent;
                        document.querySelector('.hours-repproved-mobile').textContent = document.querySelector('.hours-repproved').textContent;
                        document.querySelector('.hours-unapproved-mobile').textContent = document.querySelector('.hours-unapproved').textContent;
                    }}

                    // Ensure initial values are set for mobile view
                    document.addEventListener('DOMContentLoaded', function() {{
                        updateMobileSummary();
                        if (window.innerWidth <= 768) {{ // Verifica se a largura da janela é de 768px ou menos (modo mobile)
                                var columnsToHide = [4, 5, 6, 11]; // Índices das colunas a serem escondidas
                                columnsToHide.forEach(function(index) {{
                                    var thXPath = `//*[@id="time_entries_table"]/thead/tr/th[${{index}}]`;
                                    var th = document.evaluate(thXPath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                                    if (th) th.style.display = 'none';
                    
                                    var tdXPath = `//*[@id="time_entries_table"]/tbody/tr/td[${{index}}]`;
                                    var tds = document.evaluate(tdXPath, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
                                    for (var i = 0; i < tds.snapshotLength; i++) {{
                                        tds.snapshotItem(i).style.display = 'none';
                                    }}
                                }});
                                var thHoraInicial = document.querySelector('#time_entries_table thead tr th:nth-child(7)');
                                            if (thHoraInicial) {{
                                                thHoraInicial.textContent = 'Hora Inicial';
                                            }}

                                            var thHoraFinal = document.querySelector('#time_entries_table thead tr th:nth-child(8)');
                                            if (thHoraFinal) {{
                                                thHoraFinal.textContent = 'Hora Final';
                                            }}
                                            var thTotalHoras = document.querySelector('#time_entries_table thead tr th:nth-child(9)');
                                            if (thTotalHoras) {{
                                                thTotalHoras.textContent = 'Total Horas';
                                            }}
                            }}
                    }});
                </script>
                <style>
                    body {{
                        overflow-y: auto; /* Adiciona a barra de rolagem vertical ao body */
                        margin: 0;
                        padding: 0;
                    }}
                    #header {{
                        position: fixed;
                        top: 0;
                        width: 100%;
                        z-index: 10; /* Garante que o header fique sobre outros elementos */
                        background-color: #333333; /* Defina a cor de fundo original aqui */
                        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1); /* Adicione uma sombra para o header */
                    }}
                    .container {{
                        display: flex;
                        flex-direction: column;
                        margin-top: 60px; /* Espaço para o header fixo */
                    }}
                    .table-container th:nth-child(11), .table-container td:nth-child(11) {{
                        width: 100px; /* Define uma largura menor para a coluna "Ações" */
                        text-align: center; /* Centraliza o texto e os botões na coluna */
                    }}
                    .filters-container {{
                        display: flex;
                        flex-direction: column;
                        align-items: stretch;
                        width: 100%;
                    }}

                    .toggle-filters {{
                        background-color: #1E90FF;
                        color: white;
                        padding: 10px;
                        text-align: center;
                        border: none;
                        border-radius: 5px;
                        margin-bottom: 10px;
                        width: 100%;
                        max-width: 200px;
                        align-self: center;
                    }}

                    #time_entries_form {{
                        display: flex;
                        flex-direction: column;
                        gap: 10px;
                        width: 100%;
                    }}

                    #filter-fields {{
                        display: flex;
                        flex-direction: column;
                        gap: 10px;
                    }}

                    .filters label {{
                        font-weight: bold;
                        margin-bottom: 5px;
                    }}

                    .filters input, .filters select {{
                        width: 100%;
                        padding: 10px;
                        border: 1px solid #ddd;
                        border-radius: 5px;
                    }}

                    .legend-text {{
                        display: none; /* Oculta a legenda no modo mobile */
                    }}

                    .arrow {{
                        display: none; /* Oculta a seta no modo mobile */
                    }}
                    .table-container {{
                        width: 100%;
                        max-height: 450px; /* Define uma altura máxima para a tabela */
                    }}
                    .table-container th:nth-child(11), .table-container td:nth-child(11) {{
                        width: 120px; /* Define uma largura menor para a coluna "Ações" */
                        text-align: center; /* Centraliza o texto e os botões na coluna */
                    }}
                    .table-container td {{
                        padding: 4px; /* Diminui a altura dos td */
                        text-align: left;
                        border-bottom: 1px solid #ddd;
                        vertical-align: middle; /* Garante que o conteúdo fique alinhado verticalmente */
                        white-space: nowrap; /* Impede quebra de linha em células */
                        overflow: hidden; /* Oculta conteúdo que ultrapassa o limite */
                        text-overflow: ellipsis; /* Adiciona reticências ao conteúdo excedente */
                    }}
                    .table-container th {{
                        background-color: #f2f2f2;
                        position: sticky;
                        top: 0;
                        z-index: 1;
                        text-align: center; /* Centraliza o texto do thead */
                    }}
                    .table-container {{
                        font-size: 0.9em;
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
                    .btn-group {{
                        display: flex;
                        justify-content: center;
                        margin-top: 20px;
                    }}
                    .btn-approve-table, .btn-reject-table {{
                        display: inline-block;
                        width: 90px;
                        margin-right: 5px; /* Adiciona espaçamento entre os botões */
                        text-align: center; /* Centraliza o texto do botão */
                    }}
                    .btn-approve-table {{
                        background-color: #28a745;
                        color: white;
                        margin-bottom: 5px; /* Adiciona espaçamento vertical entre os botões */
                    }}
                    .btn-reject-table {{
                        background-color: #dc3545;
                        color: white;
                        margin-top: 5px;
                    }}
                    .btn-approve-table.disabled, .btn-reject-table.disabled {{
                        visibility: hidden; /* Torna os botões invisíveis quando desabilitados */
                    }}
                    .btn-relatorio:hover {{
                        background-color: #63B8FF; /* Azul claro ao passar o mouse */
                    }}
                    @media (max-width: 768px) {{
                        .filters-container {{
                            display: flex;
                            flex-direction: column;
                            align-items: stretch;
                            width: 100%;
                        }}
                        .toggle-filters {{
                            background-color: #1E90FF;
                            color: white;
                            padding: 10px;
                            text-align: center;
                            border: none;
                            border-radius: 5px;
                            margin: 10px 0;
                            width: 80%;
                            max-width: 130px;
                            align-self: center;
                        }}
                        #time_entries_form {{
                            display: flex;
                            flex-direction: column;
                            gap: 10px;
                            width: 100%;
                        }}
                        #filter-fields {{
                            display: flex;
                            flex-direction: column;
                            gap: 10px;
                        }}
                        .filters label {{
                            font-weight: bold;
                            margin-bottom: 5px;
                        }}
                        .filters input, .filters select {{
                            width: 100%;
                            padding: 10px;
                            border: 1px solid #ddd;
                            border-radius: 5px;
                        }}
                        .legend-text {{
                            display: none; /* Oculta a legenda no modo mobile */
                        }}
                        .arrow {{
                            display: none; /* Oculta a seta no modo mobile */
                        }}
                        .container {{
                            padding: 10px;
                            overflow-y: auto;
                            max-height: 80vh;
                        }}
                        .header-logo h1 {{
                            font-size: 1.5em;
                        }}
                        .filters {{
                            display: flex;
                            align-items: center;
                            gap: 10px;
                            margin: 0; /* Remove margem */
                            padding: 0; /* Remove padding */
                        }}
                        .table-wrapper {{
                            overflow-x: auto;
                        }}
                        .table-container {{
                            font-size: 0.9em;
                            overflow-x: scroll;
                        }}
                        .btn-group {{
                            flex-direction: column;
                            align-items: center;
                        }}
                        .btn-group .btn-relatorio {{
                            width: 180px; /* Ocupa a largura total do contêiner no modo mobile */
                            height: 40px; /* Garante que a altura do botão seja mantida */
                            margin: 0px 0;
                        }}
                        #hours-summary {{
                            display: block; /* Mostrar no modo mobile */
                        }}
                    }}
                    @media (min-width: 769px) {{
                        .toggle-filters {{
                            display: none;
                        }}
                        #time_entries_form {{
                            display: block !important;
                        }}
                        #hours-summary {{
                            display: none; /* Esconder no modo desktop */
                        }}
                        .legend-text {{
                            display: block; /* Mostrar a legenda no modo desktop */
                        }}
                        .arrow {{
                            display: inline; /* Mostrar a seta no modo desktop */
                        }}
                    }}
                    .filters label, .legend-button {{
                        color: black;
                    }}
                    table {{
                        width: 100%;
                    }}
                    #detailsPopup {{
                        display: none;
                        position: fixed;
                        top: 50%;
                        left: 50%;
                        transform: translate(-50%, -50%);
                        background-color: white;
                        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.3);
                        z-index: 1000;
                        padding: 20px;
                        border-radius: 5px;
                        max-width: 90%;
                        max-height: 90%;
                        overflow-y: auto;
                    }}
                    #detailsPopup .btn-group {{
                        display: flex;
                        justify-content: space-between;
                        margin-top: 20px;
                    }}
                    .close-button {{
                        position: absolute;
                        top: 10px;
                        right: 10px;
                        background: none;
                        border: none;
                        font-size: 1.5rem;
                        cursor: pointer;
                    }}
                    .close-button:hover {{
                        color: red;
                    }}
                                            .pagination {{
                            display: flex;
                            justify-content: center;
                            list-style-type: none;
                            padding: 0;
                            margin: 20px 0;
                        }}
                    
                        .pagination .page-item {{
                            margin: 0 5px;
                        }}
                    
                        .pagination .page-link {{
                            display: block;
                            padding: 8px 16px;
                            border: 1px solid #ddd;
                            color: #007bff;
                            text-decoration: none;
                            background-color: #fff;
                            border-radius: 4px;
                            transition: background-color 0.3s, color 0.3s;
                        }}
                    
                        .pagination .page-link:hover {{
                            background-color: #f0f0f0;
                            color: #0056b3;
                        }}
                    
                        .pagination .page-item.disabled .page-link {{
                            color: #6c757d;
                            pointer-events: none;
                            background-color: #e9ecef;
                            border-color: #dee2e6;
                        }}
                    
                        .pagination .page-item.active .page-link {{
                            z-index: 1;
                            color: #fff;
                            background-color: #007bff;
                            border-color: #007bff;
                        }}
                    @media (max-width: 768px) {{
                        #all-actions {{
                            display: none;
                        }}
                        #hours-summary-table {{
                            display: none;
                        }}
                        .mobile-actions {{
                            display: block;
                        }}
                        #hours-summary {{
                            display: block;
                        }}
                        .hours-summary {{
                            font-size: 1.2em;
                            font-weight: bold;
                            color: #333;
                            margin-top: 10px;
                        }}
                        .hours-summary p {{
                            margin: 5px 0;
                        }}
                        .hours-total-mobile, .hours-approved-mobile, .hours-unapproved-mobile {{
                            color: #1E90FF;
                        }}
                        .hours-approved-mobile {{
                            color: #28a745;
                        }}
                        .hours-repproved-mobile {{
                            color: #dc3545;
                        }}
                        .hours-unapproved-mobile {{
                            color: #bbdb03;
                        }}
                        .pagination {{
                            display: flex;
                            justify-content: center;
                            list-style-type: none;
                            padding: 0;
                            margin: 20px 0;
                        }}
                    
                        .pagination .page-item {{
                            margin: 0 5px;
                        }}
                    
                        .pagination .page-link {{
                            display: block;
                            padding: 8px 16px;
                            border: 1px solid #ddd;
                            color: #007bff;
                            text-decoration: none;
                            background-color: #fff;
                            border-radius: 4px;
                            transition: background-color 0.3s, color 0.3s;
                        }}
                    
                        .pagination .page-link:hover {{
                            background-color: #f0f0f0;
                            color: #0056b3;
                        }}
                    
                        .pagination .page-item.disabled .page-link {{
                            color: #6c757d;
                            pointer-events: none;
                            background-color: #e9ecef;
                            border-color: #dee2e6;
                        }}
                    
                        .pagination .page-item.active .page-link {{
                            z-index: 1;
                            color: #fff;
                            background-color: #007bff;
                            border-color: #007bff;
                        }}
                    }}
                    @media (min-width: 769px) {{
                        #mobile-actions-buttons {{
                            display: none; /* Tornar invisível no modo desktop */
                        }}
                    }}
                </style>
            </head>
            <body>
                <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js"></script>
                  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.11.0/umd/popper.min.js"></script>
                  <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"></script>

                <div id="header">
                    <div class="header-logo">
                        <img src="{{{{ url_for('static', filename='transparent_evt_logo.png') }}}}" alt="EVT">
                        <h1>EVT - Aprovação de Horas</h1>
                    </div>
                </div>
                <div class="container">
                    <div id="hours-summary" class="hours-summary">
                        <p>Total de Horas: <span class="hours-total-mobile">0</span></p>
                        <p>Horas Aprovadas: <span class="hours-approved-mobile">0</span></p>
                        <p>Horas Reprovadas: <span class="hours-repproved-mobile">0</span></p>
                        <p>Horas Pendentes: <span class="hours-unapproved-mobile">0</span></p>
                    </div>
                    <div id="mobile-actions-buttons" class="mobile-actions">
                        <div class="btn-group">
                            <button type="button" onclick="approveAll('{{token}}', '{{approve_entry_ids}}', {is_client})" class="btn btn-approve">Aprovar Todos</button>
                            <button type="button" onclick="rejectAll('{{token}}', '{{reject_entry_ids}}', {is_client})" class="btn btn-reject">Reprovar Todos</button>
                        </div>
                    </div>
                    <div class="filters-container">
                        <button class="toggle-filters" onclick="toggleFilters()">Filtros</button>
                        <form id="time_entries_form" method="get" action="https://timesheetqas.evtit.com/validar_selecionados?client={is_client}">
                            <fieldset class="collapsible" style="border: none;">
                                <legend class="legend-text" onclick="toggleFieldset(this);">
                                    <span class="legend-button">
                                        <span class="arrow">▶</span>
                                        Filtros
                                    </span>
                                </legend>
                                <div id="filter-fields" class="filter-fields-style" style="display: block;">
                                    <label for="filterInput">Buscar:</label>
                                    <input type="text" id="filterInput" onkeyup="filterBySelect()" placeholder="Digite para buscar...">
                                    <label for="userSelect">Usuário:</label>
                                    <select id="userSelect" onchange="filterBySelect()">
                                        <option value="ALL">Todos</option>
                                        {''.join([projeto for projeto in sorted(usuarios)])}
                                    </select>
                                    <label for="projectSelect">Projeto:</label>
                                    <select id="projectSelect" onchange="filterBySelect()">
                                        <option value="ALL">Todos</option>
                                        {''.join([projeto for projeto in sorted(projetos)])}
                                    </select>
                                    <label for="approvalSelect">Aprovado:</label>
                                    <select id="approvalSelect" onchange="filterBySelect()">
                                        <option value="ALL">Todos</option>
                                        <option value="SIM">Aprovadas</option>
                                        <option value="NÃO">Reprovadas</option>
                                        <option value="PENDENTE">Pendentes</option>
                                    </select>
                                </div>
                            </fieldset>
                        </form>
                    </div>
                    <div class="table-container">
                        {table_html}
                        <nav aria-label="Page navigation example">
                            <ul class="pagination justify-content-center">
                                <li class="page-item" id="previousPageItem">
                                    <a class="page-link" href="#" onclick="previousPage()" tabindex="-1">Anterior</a>
                                </li>
                                <li class="page-item" id="nextPageItem">
                                    <a class="page-link" href="#" onclick="nextPage()">Próximo</a>
                                </li>
                            </ul>
                        </nav>
                        <div id="all-actions" class="btn-group">
                            <button type="button" onclick="approveAll('{{token}}', '{{approve_entry_ids}}', {is_client})" class="btn btn-approve">Aprovar Todos</button>
                            <button type="button" onclick="rejectAll('{{token}}', '{{reject_entry_ids}}', {is_client})" class="btn btn-reject">Reprovar Todos</button>
                            <button type="button" onclick="sendFilteredData()" class="btn-relatorio">Enviar Relatório - Cliente</button>
                        </div>
                        <div id="selected-actions" class="btn-group">
                            <button type="button" id="approve-selected" class="btn btn-approve" data-action="aprovar">Aprovar Selecionados</button>
                            <button type="button" id="reject-selected" class="btn btn-reject" data-action="reprovar">Reprovar Selecionados</button>
                            <button type="button" onclick="sendFilteredData()" class="btn-relatorio">Enviar Relatório Selecionados - Cliente</button>
                        </div>
                    </div>
                </div>
                <div id="detailsPopup">
                    <div id="popupContent"></div>
                    <button type="button" class="close-button" onclick="hideDetailsPopup()">×</button>
                </div>
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
    total_hours = 0  # Variável para somar as horas
    approved_hours = 0  # Variável para somar as horas aprovadas
    unapproved_hours = 0  # Variável para somar as horas não aprovadas
    repproved_hours = 0

    table = '''
    <div>
      <div class="filters-container">
        <!-- Coloque aqui os elementos do filtro -->
      </div>
      <div class="table-wrapper">
        <div class="table-container">
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
            field['name'] == 'TS - Aprovado - EVT' and field['value'] == '1' for field in entry['custom_fields']
        )

        repproved = any(
            field['name'] == 'TS - Aprovado - EVT' and field['value'] == '0' for field in entry['custom_fields']
        )

        unnaproved = any(
            field['name'] == 'TS - Aprovado - EVT' and field['value'] == '' for field in entry['custom_fields']
        )

        if approved:
            approved_hours += entry['hours']
            aprovado = 'Sim'
            disable_attr = 'disabled'
        elif repproved:
            repproved_hours += entry['hours']
            aprovado = 'Não'
            disable_attr = ''
        elif unnaproved:
            unapproved_hours += entry['hours']
            aprovado = 'Pendente'
            disable_attr = ''
        else:
            unapproved_hours += entry['hours']
            aprovado = 'Pendente'
            disable_attr = ''

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
          <td class="hours-value">{entry['hours']}</td>
          <td class="approved-value">{aprovado}</td>
          <td>
            <a href="#" onclick="approveHour({entry['id']}, '{token}', {is_client}, {entry['hours']}, '{aprovado}')" class="btn btn-approve-table {'disabled' if approved else ''}" style="opacity:{'0' if approved else '1'};">Aprovar</a>
            <a href="#" onclick="rejectHour({entry['id']}, '{token}', {is_client}, {entry['hours']}, '{aprovado}')" class="btn btn-reject-table {'disabled' if approved else ''}" style="opacity:{'0' if approved else '1'};">Reprovar</a>
          </td>
        </tr>
        '''

    table += f'''
          </tbody>
        </table>
      </div>
      <br>
      </div>
      <div id="hours-summary-table" class="hours-summary">
        <p>Total de Horas: <span class="hours-total">{total_hours}</span></p>
        <p>Total de Horas Aprovadas: <span class="hours-approved">{approved_hours}</span></p>
        <p>Total de Horas Reprovadas: <span class="hours-repproved">{repproved_hours}</span></p>
        <p>Total de Horas Pendentes de Aprovação: <span class="hours-unapproved">{unapproved_hours}</span></p>
      </div>
    '''

    table += f'''
    <style>
      .table-wrapper {{
        width: 100%;
        overflow-x: auto;
      }}
      .table-container {{
        max-height: 450px;
        width: 100%;
      }}
      .table-container th:nth-child(11), .table-container td:nth-child(11) {{
        width: 80px; /* Define uma largura menor para a coluna "Ações" */
        text-align: center; /* Centraliza o texto e os botões na coluna */
      }}
      .hours-summary {{
        font-size: 1.2em;
        font-weight: bold;
        color: #333;
        margin-top: 10px;
      }}
      .hours-summary p {{
        margin: 5px 0;
      }}
      .hours-total, .hours-approved, .hours-unapproved {{
        color: #1E90FF;
      }}
      .hours-approved {{
        color: #28a745;
      }}
      .hours-repproved {{
        color: #dc3545;
      }}
      .hours-unapproved {{
        color: #bbdb03;
      }}
      thead th {{
        position: sticky;
        top: 0;
        background: white;
        z-index: 10;
        box-shadow: 0 2px 2px -1px rgba(0, 0, 0, 0.4);
        padding: 8px 4px;
        min-height: 10px;
        text-align: center;
      }}
      .table-container td {{
        white-space: nowrap;
      }}
      .btn {{
        display: inline-block;
        margin-right: 5px;
      }}
      .btn-approve-table, .btn-reject-table {{
        display: inline-block;
        width: 70px;
        margin-right: 2px;
        text-align: center;
        font-size: 0.8em;
        padding: 5px;
      }}
      .btn-approve-table {{
        background-color: #28a745;
        color: white;
        margin-bottom: 2px;
      }}
      .btn-reject-table {{
        background-color: #dc3545;
        color: white;
        margin-top: 2px;
      }}
      .btn.disabled {{
        visibility: hidden;
      }}
      @media (max-width: 768px) {{
        .container {{
            padding: 10px;
            overflow-y: auto;
            max-height: 80vh;
        }}
        .header-logo h1 {{
            font-size: 1.5em;
        }}
        .filters {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 0;
            padding: 0;
        }}
        .table-wrapper {{
            overflow-x: auto;
        }}
        .table-container {{
            font-size: 0.9em;
            overflow-x: scroll;
        }}
        .btn-group {{
            flex-direction: column;
            align-items: center;
        }}
        .btn-group .btn-relatorio {{
            width: 180px;
            height: 40px;
            margin: 0px 0;
        }}
    }}
    .filter-fields-style {{
            display: flex;
            flex-direction: column;
            gap: 15px;
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            margin-top: 15px;
        }}
        
        .filter-fields-style label {{
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }}
        
        .filter-fields-style input[type="text"],
        .filter-fields-style select {{
            width: 20%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 14px;
        }}
        
        .filter-fields-style select {{
            appearance: none;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAiIGhlaWdodD0iNSIgdmlld0JveD0iMCAwIDEwIDUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZmlsbD0iI0NDQyIgZD0iTTAgMGw1IDUgNS01eiIgLz48L3N2Zz4=') no-repeat right 10px center;
            background-size: 10px 5px;
            -webkit-appearance: none;
            -moz-appearance: none;
            appearance: none;
        }}
        
        .filter-fields-style input[type="text"]::placeholder {{
            color: #aaa;
            font-style: italic;
        }}
      @media (max-width: 768px) {{
     

        #time_entries_form {{
            display: flex;
            flex-direction: column;
            gap: 10px;
            width: 100%;
        }}

        .filters label {{
            font-weight: bold;
            margin-bottom: 5px;
        }}

        .filters input, .filters select {{
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }}
        .container {{
            padding: 10px;
            overflow-y: auto;
            max-height: 80vh;
        }}
        .header-logo h1 {{
            font-size: 1.5em;
        }}
        .filters {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 0;
            padding: 0;
        }}
        .table-wrapper {{
            overflow-x: auto;
        }}
        .table-container {{
            font-size: 0.9em;
            overflow-x: scroll;
        }}
        .btn-group {{
            flex-direction: column;
            align-items: center;
        }}
        .btn-group .btn-relatorio {{
            width: 180px;
            height: 40px;
            margin: 0px 0;
        }}
        .filter-fields-style {{
            display: flex;
            flex-direction: column;
            gap: 15px;
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            margin-top: 15px;
        }}
        
        .filter-fields-style label {{
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }}
        
        .filter-fields-style input[type="text"],
        .filter-fields-style select {{
            width: 100%;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
            font-size: 14px;
        }}
        
        .filter-fields-style select {{
            appearance: none;
            background: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAiIGhlaWdodD0iNSIgdmlld0JveD0iMCAwIDEwIDUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHBhdGggZmlsbD0iI0NDQyIgZD0iTTAgMGw1IDUgNS01eiIgLz48L3N2Zz4=') no-repeat right 10px center;
            background-size: 10px 5px;
            -webkit-appearance: none;
            -moz-appearance: none;
            appearance: none;
        }}
        
        .filter-fields-style input[type="text"]::placeholder {{
            color: #aaa;
            font-style: italic;
        }}

    }}
    </style>
    '''

    table += f'''
    <script>
      function approveHour(entryId, token, isClient, entryHours, currentStatus) {{
        fetch("{API_URL}aprovar_hora?id=" + entryId + "&token=" + token + "&client=" + isClient)
        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
        .then(result => {{
          const status = result.status;
          const body = result.body;
          if (status === 200) {{
            showAlert('Hora aprovada com sucesso!', 'success');
            updateRowApproval(entryId, true, entryHours);
            updateHourSummary(entryHours, 'approve', currentStatus);
          }} else {{
            showAlert(body.message, 'error');
          }}
        }})
        .catch(error => {{
          console.error('Erro:', error);
          showAlert('Erro ao aprovar hora.', 'error');
        }});
      }}

      function rejectHour(entryId, token, isClient, entryHours, currentStatus) {{
        fetch("{API_URL}reprovar_hora?id=" + entryId + "&token=" + token + "&client=" + isClient)
        .then(response => response.json().then(body => {{ return {{ status: response.status, body: body }}; }}))
        .then(result => {{
          const status = result.status;
          const body = result.body;
          if (status === 200) {{
            showAlert('Hora reprovada com sucesso!', 'success');
            updateRowApproval(entryId, false, entryHours);
            updateHourSummary(entryHours, 'reject', currentStatus);
          }} else {{
            showAlert(body.message, 'error');
          }}
        }})
        .catch(error => {{
          console.error('Erro:', error);
          showAlert('Erro ao reprovar hora.', 'error');
        }});
      }}

      function updateHourSummary(entryHours, action, currentStatus) {{
        const totalHoursElem = document.querySelector('.hours-total');
        const approvedHoursElem = document.querySelector('.hours-approved');
        const unapprovedHoursElem = document.querySelector('.hours-unapproved');
        const repprovedHoursElem = document.querySelector('.hours-repproved');

        let totalHours = parseFloat(totalHoursElem.textContent);
        let approvedHours = parseFloat(approvedHoursElem.textContent);
        let unapprovedHours = parseFloat(unapprovedHoursElem.textContent);
        let repprovedHours = parseFloat(repprovedHoursElem.textContent);

        if (currentStatus === 'Sim' && action === 'approve') {{
          // Não faz alteração
        }} else if (currentStatus === 'Sim' && action === 'reject') {{
          approvedHours -= entryHours;
          repprovedHours += entryHours;
        }} else if (currentStatus === 'Não' && action === 'approve') {{
          repprovedHours -= entryHours;
          approvedHours += entryHours;
        }} else if (currentStatus === 'Não' && action === 'reject') {{
          // Não faz alteração
        }} else if (currentStatus === 'Pendente' && action === 'approve') {{
          unapprovedHours -= entryHours;
          approvedHours += entryHours;
        }} else if (currentStatus === 'Pendente' && action === 'reject') {{
          unapprovedHours -= entryHours;
          repprovedHours += entryHours;
        }}

        totalHoursElem.textContent = totalHours.toFixed(1);
        approvedHoursElem.textContent = approvedHours.toFixed(1);
        unapprovedHoursElem.textContent = unapprovedHours.toFixed(1);
        repprovedHoursElem.textContent = repprovedHours.toFixed(1);
      }}

      function updateRowApproval(entryId, isApproved, entryHours) {{
        var row = document.getElementById("entry-row-" + entryId);
        var approveButton = row.querySelector('.btn-approve-table');
        var rejectButton = row.querySelector('.btn-reject-table');
        var approvedCell = row.querySelector('.approved-value');

        if (approveButton) {{
          approveButton.classList.add('disabled');
        }}
        if (rejectButton) {{
          rejectButton.classList.add('disabled');
        }}
        if (approvedCell) {{
          approvedCell.textContent = isApproved ? 'Sim' : 'Não';
        }}
      }}

      function toggleAll(source) {{
        var checkboxes = document.getElementsByName('selected_entries');
        for (var i = 0, n = checkboxes.length; i < n; i++) {{
          if (!checkboxes[i].disabled) {{
            checkboxes[i].checked = source.checked;
          }}
        }}
      }}

      function showAlert(message, type) {{
        var alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type}`;
        alertDiv.textContent = message;

        alertDiv.style.position = 'fixed';
        alertDiv.style.top = '20px';
        alertDiv.style.left = '50%';
        alertDiv.style.transform = 'translateX(-50%)';
        alertDiv.style.padding = '10px';
        alertDiv.style.zIndex = 1000;
        alertDiv.style.backgroundColor = type === 'success' ? 'green' : 'red';
        alertDiv.style.color = 'white';
        alertDiv.style.borderRadius = '5px';
        alertDiv.style.boxShadow = '0 0 10px rgba(0, 0, 0, 0.1)';
        alertDiv.style.fontSize = '16px';

        document.body.appendChild(alertDiv);

        setTimeout(() => {{
            document.body.removeChild(alertDiv);
        }}, 3000);
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
                if any("Apontamento retroativo" in error for error in error_message) or any(
                        "Foi detectado um apontamento" in error for error in error_message) or any(
                    "semana" in error for error in error_message):
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
                    field['value'] = get_recipient_by_token(token) if tipo in ['aprovar',
                                                                               'aprovar_selecionados'] else ''
                if field.get('name') == 'TS - Dt. Aprovação - EVT':
                    field['value'] = data_atual if tipo in ['aprovar', 'aprovar_selecionados'] else ''

            update_status, update_response = update_time_entry(entry_id, custom_fields)
            if update_status == 200 or 204:
                restaurar_data_original(entry_id, data_original)
                log_approval_rejection(entry_id, time_entry['spent_on'], time_entry['hours'], tipo, token)
                return {
                    "message": f"Hora {'aprovada' if tipo in ['aprovar', 'aprovar_selecionados'] else 'reprovada'} para ID: {entry_id}"}
            else:
                restaurar_data_original(entry_id, data_original)
                return {"error": "Failed to update in Redmine", "details": update_response}
        else:
            if alterar_status not in [200, 204]:
                return {"error": "Failed to temporarily change date", "details": alterar_response}
            for field in custom_fields:
                if field.get('name') == 'TS - Aprovado - EVT':
                    field['value'] = '0' if tipo in ['reprovar', 'reprovar_selecionados'] else  field['value']
                if field.get('name') == 'TS - Aprovado - CLI':
                    field['value'] = '1' if tipo in ['aprovar', 'aprovar_selecionados'] else '0'
                if field.get('name') == 'TS - Dt. Aprovação - EVT':
                    field['value'] = '' if tipo in ['reprovar', 'reprovar_selecionados'] else field['value']
                if field.get('name') == 'TS - Dt. Aprovação - CLI':
                    field['value'] = data_atual if tipo in ['aprovar', 'aprovar_selecionados'] else ''
            update_status, update_response = update_time_entry(entry_id, custom_fields)
            if update_status == 200 or 204:
                restaurar_data_original(entry_id, data_original)
                log_approval_rejection(entry_id, time_entry['spent_on'], time_entry['hours'], tipo, token)
                return {
                    "message": f"Hora {'aprovada' if tipo in ['aprovar', 'aprovar_selecionados'] else 'reprovada'} para ID: {entry_id}"}
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
