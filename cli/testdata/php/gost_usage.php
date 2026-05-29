<?php
// GOST R 34.11 / Streebog hash via PHP hash() extension
// EXPECTED: GOST3411 | hash | | info |
function gostHash($data) {
    return hash("gost-crypto", $data);
}

function streebogHash($data) {
    return hash("streebog256", $data);
}
