"""Offline evidence processing with encoded, nonexecutable JSON data."""
import base64 as _base64
import json as _json
import zlib as _zlib

CATALOGUE_BLOB = (
    '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'
    'VZVp'
)
_DATA = _json.loads(_zlib.decompress(_base64.b64decode(CATALOGUE_BLOB)))
def _text(index):
    return _DATA['strings'][index]

import argparse
import base64
import gzip
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote_plus
_ENCODED_CASES = [(_text(0), _text(1), (_text(2),), ()), (_text(3), _text(4), (), (_text(2),)), (_text(5), _text(6), (_text(7),), ()), (_text(8), _text(9), (), (_text(7),)), (_text(10), _text(11), (_text(12),), ()), (_text(13), _text(14), (), (_text(12),)), (_text(15), _text(16), (_text(17),), ()), (_text(18), _text(19), (), (_text(17),)), (_text(20), _text(21), (_text(22),), ()), (_text(23), _text(24), (), (_text(22),)), (_text(25), _text(26), (_text(27),), ()), (_text(28), _text(29), (), (_text(27),)), (_text(30), _text(31), (_text(32),), ()), (_text(33), _text(34), (), (_text(32),)), (_text(35), _text(36), (_text(37),), ()), (_text(38), _text(39), (), (_text(37),)), (_text(40), _text(1), (_text(41),), ()), (_text(42), _text(43), (), (_text(41),)), (_text(44), _text(45), (_text(46),), ()), (_text(47), _text(48), (), (_text(46),)), (_text(49), _text(50), (_text(51),), ()), (_text(52), _text(53), (), (_text(51),)), (_text(54), _text(55), (_text(56),), ()), (_text(57), _text(58), (), (_text(56),)), (_text(59), _text(60), (_text(61),), ()), (_text(62), _text(63), (), (_text(61),)), (_text(64), _text(65), (_text(66),), ()), (_text(67), _text(68), (), (_text(66),)), (_text(69), _text(70), (_text(71),), ()), (_text(72), _text(73), (), (_text(71),)), (_text(74), _text(75), (_text(76),), ()), (_text(77), _text(78), (), (_text(76),)), (_text(79), _text(80), (_text(81),), ()), (_text(82), _text(83), (), (_text(81),)), (_text(84), _text(85), (_text(86),), ()), (_text(87), _text(88), (), (_text(86),)), (_text(89), _text(90), (_text(91),), ()), (_text(92), _text(78), (), (_text(91),)), (_text(93), _text(94), (_text(95),), ()), (_text(96), _text(31), (), (_text(95),)), (_text(97), _text(98), (_text(99),), ()), (_text(100), _text(101), (), (_text(99),)), (_text(102), _text(103), (_text(104),), ()), (_text(105), _text(106), (), (_text(104),)), (_text(107), _text(108), (_text(109),), ()), (_text(110), _text(111), (), (_text(109),)), (_text(112), _text(113), (_text(114),), ()), (_text(115), _text(116), (), (_text(114),)), (_text(117), _text(118), (_text(119),), ()), (_text(120), _text(121), (), (_text(119),)), (_text(122), _text(123), (_text(124),), ()), (_text(125), _text(126), (), (_text(124),)), (_text(127), _text(128), (_text(129),), ()), (_text(130), _text(131), (), (_text(129),)), (_text(132), _text(133), (_text(134),), ()), (_text(135), _text(136), (), (_text(134),)), (_text(137), _text(138), (_text(139),), ()), (_text(140), _text(141), (), (_text(139),)), (_text(142), _text(143), (_text(144),), ()), (_text(145), _text(146), (), (_text(144),)), (_text(147), _text(148), (_text(149),), ()), (_text(150), _text(151), (), (_text(149),)), (_text(152), _text(153), (_text(154),), ()), (_text(155), _text(156), (), (_text(154),)), (_text(157), _text(158), (_text(159),), ()), (_text(160), _text(161), (), (_text(159),)), (_text(162), _text(163), (_text(164),), ()), (_text(165), _text(166), (), (_text(164),)), (_text(167), _text(168), (_text(169),), ()), (_text(170), _text(171), (), (_text(169),)), (_text(172), _text(173), (_text(174),), ()), (_text(175), _text(176), (), (_text(174),)), (_text(177), _text(178), (_text(27), _text(134)), ()), (_text(179), _text(180), (_text(27), _text(134)), ()), (_text(181), _text(182), (_text(27), _text(134)), ()), (_text(183), _text(184), (_text(139),), ()), (_text(185), _text(186), (_text(139),), ()), (_text(187), _text(188), (_text(139),), ()), (_text(189), _text(190), (_text(91),), ()), (_text(191), _text(192), (_text(91),), ()), (_text(193), _text(194), (_text(91),), ()), (_text(195), _text(196), (_text(91),), ()), (_text(197), _text(198), (_text(144),), ()), (_text(199), _text(200), (_text(144),), ()), (_text(201), _text(202), (_text(144),), ()), (_text(203), _text(204), (_text(144),), ()), (_text(205), _text(206), (_text(144),), ()), (_text(207), _text(208), (_text(144),), ()), (_text(209), _text(210), (_text(144),), ()), (_text(211), _text(212), (_text(144),), ()), (_text(213), _text(214), (_text(149),), ()), (_text(215), _text(216), (_text(149),), ()), (_text(217), _text(218), (_text(149),), ()), (_text(219), _text(220), (_text(149),), ()), (_text(221), _text(222), (_text(149),), ()), (_text(223), _text(224), (_text(154),), ()), (_text(225), _text(226), (_text(159),), ()), (_text(227), _text(228), (_text(159),), ()), (_text(229), _text(230), (_text(95), _text(124)), ()), (_text(231), _text(232), (_text(124),), ()), (_text(233), _text(234), (_text(124),), ()), (_text(235), _text(236), (), (_text(124), _text(174))), (_text(237), _text(238), (_text(169),), ()), (_text(239), _text(240), (_text(169),), ()), (_text(241), _text(242), (_text(12),), ()), (_text(243), _text(244), (_text(12),), ()), (_text(245), _text(246), (_text(17), _text(2)), ()), (_text(247), _text(248), (_text(37),), ()), (_text(249), _text(250), (_text(37),), ()), (_text(251), _text(252), (_text(37),), ()), (_text(253), _text(254), (_text(46),), ()), (_text(255), _text(256), (_text(46),), ()), (_text(257), _text(258), (_text(46),), ()), (_text(259), _text(260), (_text(46),), ()), (_text(261), _text(262), (_text(46),), ()), (_text(263), _text(264), (_text(51),), ()), (_text(265), _text(266), (_text(51),), ()), (_text(267), _text(268), (_text(56),), ()), (_text(269), _text(270), (_text(71),), ()), (_text(271), _text(272), (_text(71), _text(129)), ()), (_text(273), _text(274), (_text(71),), ()), (_text(275), _text(276), (_text(99),), ()), (_text(277), _text(278), (_text(114),), ()), (_text(279), _text(280), (_text(114),), ()), (_text(281), _text(282), (_text(114),), ()), (_text(283), _text(121), (_text(114),), ()), (_text(284), _text(285), (_text(114),), ()), (_text(286), _text(287), (_text(124),), ()), (_text(288), _text(31), (_text(32),), (_text(104), _text(95))), (_text(289), _text(106), (_text(27),), (_text(104),)), (_text(290), _text(291), (), ()), (_text(292), _text(293), (), ()), (_text(294), _text(295), (), (_text(104),)), (_text(296), _text(297), (_text(17),), ())]
_ENCODED_CASES.extend([(_text(344), _text(345), (_text(346),), ()), (_text(347), _text(348), (), (_text(346),))])
_ENCODED_CASES.extend(_DATA.get('additional_cases', []))
CASES = [(name, base64.b64decode(value).decode(_text(298)), required, forbidden) for (name, value, required, forbidden) in _ENCODED_CASES]

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(_text(299), type=Path, default=Path(_text(300)))
    p.add_argument(_text(301), type=Path, default=Path(_text(302)))
    p.add_argument(_text(303), type=Path, default=Path(__file__).with_name(_text(304)))
    p.add_argument(_text(305), action=_text(306), help=_text(307))
    args = p.parse_args(argv)
    scratch = args.scratch.resolve()
    allowed = Path(_text(302)).resolve()
    if scratch != allowed and allowed not in scratch.parents:
        p.error(_text(308))
    if args.output.suffix.lower() != _text(309):
        p.error(_text(310))
    if scratch.exists() and any(scratch.iterdir()):
        p.error(_text(311))
    scratch.mkdir(parents=True, exist_ok=True)
    (source, resolved) = (scratch / _text(312), scratch / _text(313))
    try:
        with source.open(_text(314), encoding=_text(298), newline=_text(315)) as out:
            for (index, (name, value, _, _)) in enumerate(CASES):
                row = {_text(316): {_text(317): _text(326), _text(318): _text(327) + name, _text(319): _text(328) + name + _text(329) + quote_plus(value), _text(320): _text(330), _text(321): 1767225600 + index, _text(322): 1767225600 + index, _text(323): _text(331), _text(324): _text(332), _text(325): _text(333)}}
                out.write(json.dumps(row) + _text(315))
        subprocess.run([sys.executable, _text(334), str(args.assessor.resolve()), str(source), _text(335), str(resolved), _text(336)], check=True, cwd=Path(__file__).resolve().parents[2])
        original = resolved.read_bytes()
        with args.output.open(_text(337)) as out:
            with gzip.GzipFile(fileobj=out, mode=_text(337), filename=_text(338), mtime=0) as archive:
                archive.write(original)
        if gzip.decompress(args.output.read_bytes()) != original:
            raise ValueError(_text(339))
        print(''.join([_text(340), format(len(CASES), ''), _text(341), format(args.output, '')]))
    finally:
        if not args.keep_temp:
            source.unlink(missing_ok=True)
            resolved.unlink(missing_ok=True)
            scratch.rmdir()
        else:
            print(''.join([_text(342), format(scratch, '')]), file=sys.stderr)
if __name__ == _text(343):
    main()
