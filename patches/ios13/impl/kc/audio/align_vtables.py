#!/usr/bin/env python3
"""Suggest monotonic audio vtable alignments for method review.

单独运行（仓库根目录）：
  python3 -m patches.ios13.impl.kc.audio.align_vtables --input <13 内核> [--out <目录>]
给 --out 时同时写 vtable-alignment.json。
"""
import argparse
import difflib
import json
import re

from patches.ios13.impl.kc.audio.inspect_port import Kernel, disassemble


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


def alignments(paths, audit):
    """AppleCSSPIAudio、AppleCSHTDCodecMikey 两类 12→13 的 vtable 对齐建议。"""
    kernels = {tag: Kernel(paths[tag]) for tag in ('12', '13')}
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
    return results


def main(argv=None):
    from patches.ios13.impl.kc.audio.analysis import add_arguments, from_arguments
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_arguments(parser)
    args = parser.parse_args(argv)
    analysis = from_arguments(args)
    results = alignments(analysis.paths, analysis.port_audit())
    if args.out is not None:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'vtable-alignment.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
