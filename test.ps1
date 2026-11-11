Write-Host "== Python: regenerate data and models =="
python sim\can_bus_sim.py
python sim\frames_to_bits.py
python sim\firewall_model.py

Write-Host "`n== Parser testbench =="
iverilog -g2012 -I tb -o tb\parser.vvp tb\tb_can_parser.v rtl\can_parser.v
$p = vvp tb\parser.vvp | Out-String
Write-Host $p

Write-Host "== Firewall testbench =="
iverilog -g2012 -I tb -o tb\fw.vvp tb\tb_firewall.v rtl\can_firewall.v
$f = vvp tb\fw.vvp | Out-String
Write-Host $f

Write-Host "== TDoA model =="
python sim\tdoa.py

Write-Host "`n== Autoencoder =="
python ml\autoencoder.py

if (($p -match "PASS") -and ($f -match "PASS")) {
    Write-Host "ALL TESTS PASSED" -ForegroundColor Green
} else {
    Write-Host "TESTS FAILED" -ForegroundColor Red
    exit 1
}