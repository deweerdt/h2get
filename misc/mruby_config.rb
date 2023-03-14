MRuby::Lockfile.disable

MRuby::Build.new do |conf|
  # load specific toolchain settings

  # Gets set by the VS command prompts.
  if ENV['MRUBY_TOOLCHAIN']
    toolchain ENV['MRUBY_TOOLCHAIN']
  elsif ENV['VisualStudioVersion'] || ENV['VSINSTALLDIR']
    toolchain :visualcpp
  else
    toolchain :gcc
  end

  # enable_debug

  # # gperf settings
  # conf.gperf do |gperf|
  #   gperf.command = 'gperf'
  #   gperf.compile_options = %q[-L ANSI-C -C -p -j1 -i 1 -g -o -t -N mrb_reserved_word -k"1,3,$" "%{infile}" > "%{outfile}"]
  # end

  # use mrbgems
  Dir.glob("../mruby-*/mrbgem.rake") do |x|
    g = File.basename File.dirname x
    if g == 'mruby-onig-regexp'
      conf.gem "../deps/#{g}" do |c|
        c.bundle_onigmo
      end
    else
      conf.gem "../deps/#{g}"
    end
  end

  # include all the core GEMs
  conf.gembox 'full-core'

  conf.cc.defines << "MRB_INT64"

end
