#!/usr/bin/env python3

import sys
import json

# ENTER YOUR HEX PUBKEY(S) BELOW:
whitelist = {
  "hex-pubkey-1",
  "hex-pubkey-2"
}

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)

def accept(request):
  response = {
    'id' : request['event']['id']
  }

  response['action'] = 'accept'
  r = json.dumps(response,separators=(',', ':')) # output JSONL
  print(r, end='\n', file=sys.stdout, flush=True)

def reject(request):
  response = {
    'id' : request['event']['id']
  }

  response['action'] = 'reject'
  response['msg'] = f"blocked: pubkey {request['event']['pubkey']} not in whitelist. | SOURCE: {request['sourceInfo']}"
  r = json.dumps(response,separators=(',', ':')) # output JSONL
  print(r, end='\n', file=sys.stdout, flush=True)

def main():
  for line in sys.stdin:
    request = json.loads(line)

    try:
      if request['type'] == 'lookback':
        sys.exit(0)
    except KeyError:
      eprint("input without type in write policy plugin")
      sys.exit(0)

    if request['type'] != 'new':
      eprint("unexpected request type in write policy plugin")
      sys.exit(0)

    try:
      if not request['event']['id']:
        eprint("input without event id in write policy plugin")
        sys.exit(0)
    except KeyError:
      eprint("input without event id in write policy plugin")
      sys.exit(0)

    try:
      if request['event']['pubkey'] in whitelist:
        accept(request)
      elif int(request['event']['kind']) == 10002:
        accept(request)
      elif request.get("event", {}).get("tags"):
        if p_tags:= [x for x in request['event']['tags'] if x[0] == 'p']:
          pubkeys = [x[1] for x in p_tags]
          if whitelist.intersection(pubkeys):
            accept(request)
          else:
            reject(request)
        else:
          reject(request)
      else:
        reject(request)
    except KeyError:
      eprint("poorly formed event input in write policy plugin")
      sys.exit(0)

if __name__=='__main__':
  main()