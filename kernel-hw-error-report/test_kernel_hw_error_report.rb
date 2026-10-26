require 'minitest/autorun'
require_relative 'kernel_hw_error_report'
class T < Minitest::Test
  def test_classify
    lines = ["[1.0] EDAC MC0: 1 CE on DIMM_A1", "[2.0] mce: [Hardware Error]: Machine check events logged",
             "[3.0] blk_update_request: I/O error, dev sda, sector 123", "[4.0] ata1.00: failed command: READ DMA",
             "[5.0] EXT4-fs error (device sda1): ext4_lookup", "[6.0] normal boot message", "[7.0] nvme0: I/O error"]
    f = classify(lines).map { |x| [x.cls, x.sev, x.count] }
    assert_includes f, ['memory', 'CRIT', 1]
    assert_includes f, ['memory', 'WARN', 1]
    assert_includes f, ['disk', 'CRIT', 1]
    assert_includes f, ['disk', 'WARN', 1]
    assert_includes f, ['filesystem', 'CRIT', 1]
    assert_includes f, ['nvme', 'WARN', 1]
    assert_empty classify(["[1] all fine"])
  end
end
