from __future__ import print_function
from volatility.plugins.common import AbstractWindowsCommand
import volatility.win32.tasks as vtasks
import volatility.utils as utils
import volatility.debug as debug
import pefile
import hashlib
import distorm3



def Disassemble(data, start, bits='32bit', stoponret=False):


    if bits == '32bit':
        mode = distorm3.Decode32Bits
    else:
        mode = distorm3.Decode64Bits

    for o, _, i, h in distorm3.DecodeGenerator(start, data, mode):
        if stoponret and i.startswith("RET"):
            raise StopIteration
        yield o, i, h


class MalfindPlus(AbstractWindowsCommand):
    """Find the injected code"""

    def __init__(self, config, *args, **kwargs):

        AbstractWindowsCommand.__init__(self, config, *args, **kwargs)

        self._config.add_option('PID', short_option = 'p', default = None,
                      help = 'Operate on these Process IDs (comma-separated)',
                      action = 'store', type = 'str')
        self.addr_space = utils.load_as(self._config)

        self.nx_mask = 1 << 63


    def filter_tasks(self, tasks):
        """Filter the process"""
        if self._config.PID is None:
            return tasks

        try:
            pidlist = [int(p) for p in self._config.PID.split(',')]
        except ValueError:
            debug.error("Invalid PID {0}".format(self._config.PID))

        return [t for t in tasks if t.UniqueProcessId in pidlist]


    def calculate(self):
        """Main Function"""
        #get process object
        self.wow64 = False
        self.tasks = list(vtasks.pslist(self.addr_space))
        tasks_list = self.filter_tasks(vtasks.pslist(self.addr_space))

        #analyze the process(es)
        for task in tasks_list:
            if task.IsWow64:
                self.wow64 = True
            for data in self.analyze(task):
                yield data


    def analyze(self, task):
        """Analyze the process and return suspicious pages"""
        info = "\rAnalysing PID: {0:d} - {1:s}\n"
        self.pid = task.UniqueProcessId
        self.TaskName = task.ImageFileName
        print(info.format(self.pid, self.TaskName), end='')
        # get the process address space
        ps_ad = task.get_process_address_space()
        user_pages = self.get_user_pages(ps_ad)
        user_execute_pages = self.get_user_execute_pages(user_pages)
        vads = self.get_vads(task)
        mapped_file_vads, unmapped_file_vads = self.classify_vads(vads)
        unreference_pages = self.get_unreferenced_pages(vads, user_execute_pages, ps_ad)

        mapped_file_execute_pages = self.get_mapped_file_pages_hashs(user_execute_pages, mapped_file_vads, ps_ad)


        suspicious_mapped_file_pages = self.find_suspicious_mapped_file_pages(mapped_file_execute_pages)
        suspicious_unmapped_file_pages = self.get_unmapped_file_pages(user_execute_pages, unmapped_file_vads)

        yield task, suspicious_mapped_file_pages, suspicious_unmapped_file_pages, ps_ad, unreference_pages


    def render_text(self, outfd, data):
        for task, suspicious_mapped_file_pages, suspicious_unmapped_file_pages, ps_ad, unreference_pages in data:
            # output process info
            info = "Analysing PID: {0:d} - {1:s}\n"
            pid = task.UniqueProcessId
            outfd.write(info.format(pid, task.ImageFileName))

            if len(suspicious_mapped_file_pages) == 0 and len(suspicious_unmapped_file_pages) == 0 and len(unreference_pages) == 0:
                info = "There is no suspicious page in {0:s}\n"
                outfd.write(info.format(task.ImageFileName))
            else:
                for path, addr in suspicious_mapped_file_pages:
                    info = "Found suspicious mapped file page(s) at {0:#x}\nPath:{1:s}\n"
                    outfd.write(info.format(addr, path))
                    content = ps_ad.read(addr, 0x100)

                    """outfd.write("{0}\n".format("\n".join(
                        ["{0:#010x}  {1:<48}  {2}".format(0 + o, h, ''.join(c))
                         for o, h, c in utils.Hexdump(content)
                         ])))"""

                    """outfd.write("\n".join(
                        ["{0:#010x} {1:<16} {2}".format(o, h, i)
                         for o, i, h in Disassemble(content, 0)
                         ]))"""

                for addr, size in suspicious_unmapped_file_pages:
                    info = "Found suspicious unmapped file page(s) at {0:x}\n"
                    outfd.write(info.format(addr))
                    content = ps_ad.read(addr, 0x100)
                    """outfd.write("{0}\n".format("\n".join(
                        ["{0:#010x}  {1:<48}  {2}".format(0 + o, h, ''.join(c))
                         for o, h, c in utils.Hexdump(content)
                         ])))"""

                    """outfd.write("\n".join(
                        ["{0:#010x} {1:<16} {2}".format(o, h, i)
                         for o, i, h in Disassemble(content, 0)
                         ]))"""

                for addr, size in unreference_pages:
                    info = "Found unreferenced page(s) at {0:x} size:{1:x}\n"
                    outfd.write(info.format(addr, size))


    def get_user_pages(self, ps_ad):
        """Return a list of all accessible userspace virtual address pages"""
        info = "\rGetting user address space pages PID: {0:d} - {1:s}\n"
        print(info.format(self.pid, self.TaskName), end='')
        all_pages = ps_ad.get_available_pages(with_pte=True)
        pages = []
        if self.wow64:
            for page in all_pages:
                if page[1] < 0x80000000:
                    # not always a valid assumption (eg 3GB switch)
                    pages.append(page)
            return pages
        else:
            for page in all_pages:
                if page[1] < 0x800000000000:
                    pages.append(page)
            return pages


    def get_user_execute_pages(self, user_pages):
        """Get all pages with execute protection in user address sapce"""
        info = "\rGetting user address space pages with execute protection PID: {0:d} - {1:s}\n"
        print(info.format(self.pid, self.TaskName), end='')
        user_execute_pages = []
        for pte, addr, size in user_pages:
            if not pte & self.nx_mask:
                user_execute_pages.append([addr, size])
        return user_execute_pages


    def get_vads(self, task):
        """Get all vad nodes"""
        info = "\rGetting VADs PID: {0:d} - {1:s}\n"
        print(info.format(self.pid, self.TaskName), end='')
        vads = []
        for vad in task.VadRoot.traverse():
            vads.append(vad)
        return vads


    def classify_vads(self,vads):
        """Classify the VADs to mapped file VADs and unmapped file VADs"""
        extensions = [".dll", ".exe", ".drv", ".cpl", ".ocx", ".mui", "inmd"]
        mapped_file_vads = []
        unmapped_file_vads = []
        for vad in vads:
            try:
                if vad.FileObject:
                    if str(vad.FileObject.FileName)[-4:] in extensions:
                        mapped_file_vads.append(vad)
                    else:
                        unmapped_file_vads.append(vad)
                else:
                    unmapped_file_vads.append(vad)
            except AttributeError:
                unmapped_file_vads.append(vad)
        return mapped_file_vads, unmapped_file_vads

    def get_unreferenced_pages(self, vads, user_execute_pages, ps_ad):
        """Get all unreferenced pages"""
        unferenced = []
        for addr, size in user_execute_pages:
            is_in = False
            for vad in vads:
                if vad.Start <= addr <= vad.End:
                    is_in = True
                    break
            if not is_in:
                if ps_ad.read(addr, size) != '\x00' * size:
                    unferenced.append(addr, size)
        return unferenced

    def get_mapped_file_pages_hashs(self, user_execute_pages, vads, ps_ad):
        """Get all execute mapped file pages hashs"""
        info = "\rCalculating hashs of mapped file pages in memory PID: {0:d} - {1:s}\n"
        print(info.format(self.pid, self.TaskName), end='')
        mapped_file_pages = {}
        for vad in vads:
            path = str(vad.FileObject.FileName)
            mapped_file_pages[path] = [vad.Start, []]
            for addr, size in user_execute_pages:
                if vad.Start <= addr <= vad.End:
                    hash = self.cal_hash(ps_ad, addr, size)
                    mapped_file_pages[path][1].append([addr, hash])
        return mapped_file_pages


    def cal_hash(self,ps_ad, addr, size):
        """Calculate the hash for specific address space"""
        content = ps_ad.read(addr, size)
        hash = hashlib.md5(content).hexdigest()
        return hash


    def find_suspicious_mapped_file_pages(self, mapped_file_execute_pages):
        """Find the suspicious mapped file pages"""
        suspicious_mapped_file_pages = []
        for path in mapped_file_execute_pages.keys():
            base = mapped_file_execute_pages[path][0]
            hashs_disk = self.cal_disk_hashs(path, base)
            for addr, hash in mapped_file_execute_pages[path][1]:
                if hash not in hashs_disk:
                    suspicious_mapped_file_pages.append([path, addr])
        return suspicious_mapped_file_pages


    def get_unmapped_file_pages(self,user_execute_pages, unmapped_file_vads):
        """Get all execute unmapped file pages"""
        info = "\rGetting unmapped file pages PID: {0:d} - {1:s}\n"
        print(info.format(self.pid, self.TaskName), end='')
        unmapped_file_pages = []
        for vad in unmapped_file_vads:
            for addr, size in user_execute_pages:
                if vad.Start <= addr <= vad.End:
                    unmapped_file_pages.append([addr, size])
        return unmapped_file_pages

    def cal_disk_hashs(self, path, base):
        """Built the hash set of PE file in disk"""

        path = 'C:' + path
        info = "\rCalculating disk hashs at {0} PID: {1:d} - {2:s}\n"
        print(info.format(path, self.pid, self.TaskName), end='')
        path = path.replace('\\', '/')
        try:
            pe_disk = pefile.PE(path)
        except OSError:
            print("Warning - Disk file {0:s} not found\n".format(path.replace('/', '\\')))
            hashs_disk = []
            return hashs_disk
        pe_memory = pe_disk.get_memory_mapped_image(ImageBase=base)
        while len(pe_memory) % 0x1000 != 0:
            pe_memory = pe_memory + '\x00'
        hashs_disk = []
        start = 0
        while start != len(pe_memory):
            hash = hashlib.md5(pe_memory[start:start + 0x1000])
            hashs_disk.append(hash.hexdigest())
            start = start + 0x1000
        pe_disk.close()
        return hashs_disk
