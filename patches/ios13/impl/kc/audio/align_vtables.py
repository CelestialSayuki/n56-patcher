#!/usr/bin/env python3
"""Suggest monotonic audio vtable alignments for method review."""
import difflib
import json
import re

from inspect_port import HERE, Kernel, PATHS, disassemble


def signature(kernel, address):
    tokens = []
    for instruction in disassemble(kernel, address, 128):
        operands = re.sub(r'#-?0x[0-9a-f]+|#-?\d+', '#', instruction.op_str)
        tokens.append(instruction.mnemonic + ' ' + operands)
        if instruction.mnemonic in ('ret', 'br'):
            break
    return tokens


def align(old, new):
    gap = len(new) - len(old)
    scores = {(0, 0): 0}
    previous = {}
    similarities = {}
    for index in range(len(old) + 1):
        for inserted in range(gap + 1):
            state = (index, inserted)
            if state not in scores:
                continue
            score = scores[state]
            if inserted < gap:
                following = (index, inserted + 1)
                if score > scores.get(following, -1):
                    scores[following] = score
                    previous[following] = (state, 'insert')
            if index < len(old):
                target = index + inserted
                similarity = difflib.SequenceMatcher(
                    None, old[index], new[target], autojunk=False).ratio()
                similarities[index, target] = similarity
                following = (index + 1, inserted)
                if score + similarity > scores.get(following, -1):
                    scores[following] = score + similarity
                    previous[following] = (state, 'match')
    pairs, additions = [], []
    state = (len(old), gap)
    while state != (0, 0):
        preceding, action = previous[state]
        index, inserted = preceding
        if action == 'insert':
            additions.append(index + inserted)
        else:
            pairs.append(dict(old_slot=index, new_slot=index + inserted,
                              similarity=round(similarities[index, index + inserted], 3)))
        state = preceding
    return dict(suggested_inserted_slots13=additions[::-1],
                method_pairs=pairs[::-1], requires_method_review=True)


def main():
    audit = json.loads((HERE / 'port-audit.json').read_text())
    kernels = {tag: Kernel(PATHS[tag]) for tag in ('12', '13')}
    results = {}
    for name in ('AppleCSSPIAudio', 'AppleCSHTDCodecMikey'):
        tables = {
            tag: next(c['slots'] for c in audit['classes'][tag] if c['name'] == name)
            for tag in kernels}
        signatures = {tag: [signature(kernels[tag], p) for p in tables[tag]]
                      for tag in kernels}
        result = align(signatures['12'], signatures['13'])
        results[name] = result
        weak = sum(p['similarity'] < .55 for p in result['method_pairs'])
        print(name, 'suggested inserted slots', result['suggested_inserted_slots13'],
              'pairs requiring closer review', weak)
    (HERE / 'vtable-alignment.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
