/**
 * Test vector for Z85
 */
sjcl.test.vector.z85 =
[
/**
 * Test case from http://rfc.zeromq.org/spec:32/Z85/:
 * | 0x86 | 0x4F | 0xD2 | 0x6F | 0xB5 | 0x59 | 0xF7 | 0x5B | encodes as
 * | H | e | l | l | o | W | o | r | l | d |
 */
["864fd26fb559f75b", "HelloWorld"],
/**
 * Sanity tests:
 */
["00000000", "00000"],
["ffffffff", "%nSc0"],
/**
 * Test cases from PyZMQ (https://github.com/zeromq/pyzmq):
 */
["bb88471d65e2659b30c55a5321cebb5aab2b70a398645c26dca2b2fcb43fc518",
 "Yne@$w-vo<fVvi]a<NY6T1ed:M$fCG*[IaLV{hID"],
["7bb864b489afa3671fbe69101f94b38972f24816dfb01b51656b3fec8dfd0888",
 "D:)Q[IlAW!ahhC2ac:9*A}h:p?([4%wOTJ%JR%cs"],
["54fcba24e93249969316fb617c872bb0c1d1ff14800427c594cbfacf1bc2d652",
 "rq:rM>}U?@Lns47E1%kR.o@n%FcmmsL/@{H8]yf7"],
["8e0bdd697628b91d8f245587ee95c5b04d48963f79259877b49cd9063aead3b7",
 "JTKVSB%%)wK0E.X)V>+}o?pNmC{O&4W4b!Ni{Lh6"],
/**
 * Thomas Hobbes' "Leviathan", Part I, Chapter VI:
 * (The "classic" Base85 example, also the second Wikipedia logo):
 *
 * "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure"
 *
 * The period at the end of the sentence has been omitted,
 * since keeping it requires padding the Hex string to align to 4-bytes.
 */
 ["4d616e2069732064697374696e677569736865642c206e6f74206f6e6c792062792068697320726561736f6e2c2062757420627920746869732073696e67756c61722070617373696f6e2066726f6d206f7468657220616e696d616c732c2077686963682069732061206c757374206f6620746865206d696e642c20746861742062792061207065727365766572616e6365206f662064656c6967687420696e2074686520636f6e74696e75656420616e6420696e6465666174696761626c652067656e65726174696f6e206f66206b6e6f776c656467652c2065786365656473207468652073686f727420766568656d656e6365206f6620616e79206361726e616c20706c656173757265",
  "o<}]Zx(+zcx(!xgzFa9aB7/b}efF?GBrCHty<vdjC{3^mB0bHmvrlv8efFzABrC4raARphB0bKrzFa9dvr9GfvrlH7z/cXfA=k!qz//V7AV!!dx(do{B1wCTxLy%&azC)tvixxeB95Kyw/#hewGU&7zE+pvBzb98ayYQsvixJ2A=U/nwPzi%v}u^3w/$R}y?WJ}BrCpnaARpday/tcBzkSnwN(](zE:(7zE^r<vrui@vpB4:azkn6wPzj3x(v(iz!pbczF%-nwN]B+efFIGv}xjZB0bNrwGV5cz/P}xC4Ct#zdNP{wGU]6ayPekay!&2zEEu7Abo8]B9hIm"]
];
