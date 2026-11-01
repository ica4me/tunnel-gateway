"""Client exports intentionally include secrets, never audit logs."""
import base64
import copy
import json
from urllib.parse import quote, urlencode


def b64(value):
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')


def client_config(account, settings, network='ws', tls=False):
    protocol=account['protocol']
    secret=account['secret']
    port=settings['ports']['https' if tls else 'http']
    user={'id':secret,'level':0}
    if protocol=='vless': user['encryption']='none'
    if protocol in ('vless','vmess'):
        outbound_settings={'vnext':[{'address':'ADDRESS','port':port,'users':[user]}]}
    else:
        server={'address':'ADDRESS','port':port,'password':secret,'level':0}
        if protocol=='ss': server['method']=settings.get('ss_method','chacha20-ietf-poly1305')
        outbound_settings={'servers':[server]}
    stream={'network':network,'security':'tls' if tls else 'none'}
    if network=='ws': stream['wsSettings']={'path':settings['ws_paths'][protocol],'headers':{'Host':'HOST'}}
    else: stream['grpcSettings']={'serviceName':settings['grpc_names'][protocol]}
    if tls: stream['tlsSettings']={'serverName':settings['domain'],'allowInsecure':False}
    return {'inbounds':[],'outbounds':[{'protocol':'shadowsocks' if protocol=='ss' else protocol,'settings':outbound_settings,'streamSettings':stream,'mux':{'enabled':False},'tag':protocol.upper()}],'socks_engine_udpgw_port':settings['ports']['udpgw'][0]}


def account_detail(account, settings):
    result=copy.deepcopy(account)
    protocol=account['protocol']
    domain=settings['domain']
    result.update(domain=domain,ports=settings['ports'],quota_supported=protocol!='ssh',udpgw=settings['ports']['udpgw'])
    if protocol=='ssh':
        result['payloads']=[
            'GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]',
            'GET / HTTP/1.1[crlf]Host: blog.ruangguru.com[crlf]Connection: Keep-Alive[crlf][crlf]PATCH / HTTP/1.1[crlf]Host: [host][crlf]Upgrade:websocket[crlf][crlf][split]HTTP/enhanced 200 Ok[crlf]',
            'CONNECT [host]:443 HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]']
        result['warnings']=['SSH WS sebaiknya langsung ke IP VPS, bukan Cloudflare.','Kuota SSH tidak didukung; limit adalah jumlah sesi login.']
        return result
    result.update(ws_path=settings['ws_paths'][protocol],grpc_name=settings['grpc_names'].get(protocol),ss_method=settings.get('ss_method','chacha20-ietf-poly1305'))
    links=[]
    variants=[('ws',True),('ws',False)]
    if protocol!='ss': variants.append(('grpc',True))
    for network,tls in variants:
        port=settings['ports']['https' if tls else 'http']
        path=settings['ws_paths'][protocol] if network=='ws' else settings['grpc_names'][protocol]
        label=account['username']+'-'+network+('-tls' if tls else '')
        if protocol=='vmess':
            value={'v':'2','ps':label,'add':domain,'port':str(port),'id':account['secret'],'aid':'0','scy':'auto','net':network,'type':'none','host':domain,'path':path,'tls':'tls' if tls else '', 'sni':domain}
            links.append('vmess://'+base64.b64encode(json.dumps(value).encode()).decode())
        else:
            query={'security':'tls' if tls else 'none','type':network,'host':domain,'sni':domain}
            query['path' if network=='ws' else 'serviceName']=path
            if protocol=='vless': query['encryption']='none'
            credential=quote(account['secret'],safe='')
            if protocol=='ss': credential=b64(result['ss_method']+':'+account['secret'])
            links.append(protocol+'://'+credential+'@'+domain+':'+str(port)+'?'+urlencode(query)+'#'+quote(label))
    result['links']=links
    result['client_config']=client_config(account,settings)
    result['placeholders']={'ADDRESS':'IP VPS atau IP Cloudflare','HOST':'Domain/Host header pilihan; TLS SNI sesuai domain sertifikat'}
    result['warnings']=['SS WS memakai query ekstensi Xray; bukan SIP002 transport universal.'] if protocol=='ss' else []
    return result
