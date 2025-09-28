# hubspot.py

import json
import secrets
from typing import List
from redis_client import add_key_value_redis, delete_key_redis, get_value_redis
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio
import base64
import requests
import hashlib
from integrations.integration_item import IntegrationItem


CLIENT_ID = '60a80abe-1ea5-4438-a1d8-040239f48314'
CLIENT_SECRET = 'fae82c98-d059-4437-9734-0683baaa5a65'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
scope = f"oauth%20crm.objects.contacts.read%20files"
authorization_url = f'https://app.hubspot.com/oauth/authorize?client_id={CLIENT_ID}&scope={scope}&redirect_uri={REDIRECT_URI}'


async def authorize_hubspot(user_id, org_id):
    state_data = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode('utf-8')).decode('utf-8')

    code_verifier = secrets.token_urlsafe(32)
    m = hashlib.sha256()
    m.update(code_verifier.encode('utf-8'))
    code_challenge = base64.urlsafe_b64encode(m.digest()).decode('utf-8').replace('=', '')

    auth_url = f'{authorization_url}&state={encoded_state}&code_challenge={code_challenge}&code_challenge_method=S256'
    await asyncio.gather(
        add_key_value_redis(f'hubspot_state:{org_id}:{user_id}', json.dumps(state_data), expire=600),
        add_key_value_redis(f'hubspot_verifier:{org_id}:{user_id}', code_verifier, expire=600),
    )

    return auth_url

async def oauth2callback_hubspot(request: Request):
    print('HubSpot OAuth callback received')
    if request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=request.query_params.get('error_description'))
    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')
    state_data = json.loads(base64.urlsafe_b64decode(encoded_state).decode('utf-8'))

    original_state = state_data.get('state')
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')

    saved_state, code_verifier = await asyncio.gather(
        get_value_redis(f'hubspot_state:{org_id}:{user_id}'),
        get_value_redis(f'hubspot_verifier:{org_id}:{user_id}'),
    )

    if not saved_state or original_state != json.loads(saved_state).get('state'):
        raise HTTPException(status_code=400, detail='State does not match.')

    async with httpx.AsyncClient() as client:
        response, _, _ = await asyncio.gather(
            client.post(
                'https://api.hubapi.com/oauth/v1/token',
                data={
                    'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': REDIRECT_URI,
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                    'code_verifier': code_verifier.decode('utf-8'),
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            ),
            delete_key_redis(f'hubspot_state:{org_id}:{user_id}'),
            delete_key_redis(f'hubspot_verifier:{org_id}:{user_id}'),
        )
        print(f"HubSpot token response: {response.status_code}")
        print(f"HubSpot token response body: {response.text}")

        if response.status_code != 200:
            raise HTTPException(status_code=400, detail=f'Token exchange failed: {response.text}')

    await add_key_value_redis(f'hubspot_credentials:{org_id}:{user_id}', json.dumps(response.json()), expire=600)
    
    close_window_script = """
    <html>
        <script>
            window.close();
        </script>
    </html>
    """
    return HTMLResponse(content=close_window_script)

async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f'hubspot_credentials:{org_id}:{user_id}')
    if not credentials:
        raise HTTPException(status_code=400, detail='No credentials found.')
    credentials = json.loads(credentials)
    await delete_key_redis(f'hubspot_credentials:{org_id}:{user_id}')

    return credentials


def create_integration_item_metadata_object(
    response_json: dict, item_type: str, parent_id=None, parent_name=None
) -> IntegrationItem:
    parent_id = None if parent_id is None else parent_id + '_HubSpot'
    if item_type == 'Contact':
        properties = response_json.get('properties', {})
        name = f"{properties.get('firstname', '')} {properties.get('lastname', '')}"
        email = properties.get('email', '')
        # Convert creation date string to datetime if available
        creation_time = None
        if properties.get('createdate'):
            from datetime import datetime
            try:
                creation_time = datetime.fromisoformat(properties.get('createdate').replace('Z', '+00:00'))
            except:
                creation_time = None
    else:
        name = response_json.get('name', 'Unknown')
        email = None
        creation_time = None
        properties = response_json

    integration_item_metadata = IntegrationItem(
        id=str(response_json.get('id', '')) + '_' + item_type,
        name=name,
        type=item_type,
        parent_id=parent_id,
        parent_path_or_name=parent_name,
        email=email,
        creation_time=creation_time,
        properties=properties,
    )
    return integration_item_metadata

async def get_items_hubspot(credentials) -> List[IntegrationItem]:
    credentials = json.loads(credentials)
    access_token = credentials.get('access_token')

    if not access_token:
        raise HTTPException(status_code=400, detail='No access token found')

    list_of_integration_item_metadata = []

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                'https://api.hubapi.com/crm/v3/objects/contacts',
                headers={'Authorization': f'Bearer {access_token}'},
                params={'limit': 10} 
            )
            print(response.json())
            if response.status_code == 200:
                contacts_data = response.json()
                for contact in contacts_data.get('results', []):
                    list_of_integration_item_metadata.append(
                        create_integration_item_metadata_object(contact, 'Contact')
                    )
            else:
                print(f'Failed to fetch contacts: {response.status_code} - {response.text}')
                raise HTTPException(status_code=400, detail=f'Failed to fetch HubSpot data: {response.text}')

    except Exception as e:
        print(f'Error fetching HubSpot items: {str(e)}')
        raise HTTPException(status_code=400, detail=f'Error fetching HubSpot data: {str(e)}')

    print(f'HubSpot integration items: {list_of_integration_item_metadata}')
    return list_of_integration_item_metadata