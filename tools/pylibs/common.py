import os, sys, datetime, time, tempfile, random
import ConfigParser
import subprocess as sp
import numpy as np
import matplotlib.ticker as mt

# Class to load INI style configuration files (extended: also supports list values)
class EConfig():
	def __init__(self, cfgfile, debug=False):
		self._debug = debug
		self._cfg = ConfigParser.ConfigParser()
		self._cfg.read(cfgfile)

		if self._debug:
			for s in self._cfg.sections():
				for o in self._cfg.options(s):
					v = self.getlist(s, o)
					print "EConfig> %s.%s = %s" % (s, o, str(v))

	def sections(self):
		return self._cfg.sections()

	def options(self, section):
		return self._cfg.options(section)

	def has_section(self, section):
		return self._cfg.has_section(section)

	def has_option(self, section, option):
		return self._cfg.has_option(section, option)

	def get(self, section, option):
		return self._cfg.get(section, option)

	def getlist(self, section, option):
		v = self._cfg.get(section, option)
		if (v[0] == "[") and (v[-1] == "]"):
			if self._debug:
				print "EConfig> %s.%s detected as list value" % (section, option)
			return eval(v)
		return [v]

	def getint(self, section, option):
		return self._cfg.getint(section, option)

	def getintlist(self, section, option):
		l = self.getlist(section, option)
		r = list()
		for e in l:
			r.append(int(e))
		return r

	def getfloat(self, section, option):
		return self._cfg.getfloat(section, option)

	def getfloatlist(self, section, option):
		l = self.getlist(section, option)
		r = list()
		for e in l:
			r.append(float(e))
		return r

	def getboolean(self, section, option):
		return self._cfg.getboolean(section, option)

	def getbooleanlist(self, section, option):
		l = self.getlist(section, option)
		r = list()
		for e in l:
			r.append(boolean(e))
		return r

# Returns a number in a human-readable string
class HumanReadableFormatter(mt.Formatter):
	def __init__(self, unit="", infix="", multiple=1000, precision=3, leading_zeros=0, fixed_float=False):
		self._big_prefixes   = ["K", "M", "G", "T", "P", "E", "Z", "Y"]
		self._small_prefixes = ["m", "u", "n", "p", "f", "a", "z", "y"]

		self.unit=unit
		self.infix=infix
		self.multiple=multiple
		self.precision=precision
		self.fixed_float=fixed_float
		self.leading_zeros=leading_zeros

	def __call__(self, num, _unused=0):
		num = float(num)
		prefix = ""
		sign = ""
		o = -1
		if num < 0:
			sign = "-"
			num *= -1
	
		if num < 1 and num != 0:
			while num < 1 and o < len(self._small_prefixes) - 1:
				num *= self.multiple
				o += 1
			if o != -1:
				prefix = "%s%s" % (self._small_prefixes[o], self.infix)
		else:
			while num >= self.multiple and o < len(self._big_prefixes) - 1:
				num /= self.multiple
				o += 1
			if o != -1:
				prefix = "%s%s" % (self._big_prefixes[o], self.infix)
		
		if self.fixed_float:
			return ("%%s%%0%d.%df %%s%s" % (self.leading_zeros, self.precision, self.unit)) % (sign, num, prefix)
		else:
			return ("%%s%%0%d.%dg %%s%s" % (self.leading_zeros, self.precision + 1, self.unit)) % (sign, num, prefix)

def human_readable(num, unit="", infix="", multiple=1000, precision=3, leading_zeros=0):
	f = HumanReadableFormatter(unit, infix, multiple, precision, leading_zeros)
	return f(num)


# Calculates the first order of difference (f'(x)) by taking step size of
# x-axis into account.
#
# nparray:	two-dimensional array where the columns
# x_column:	column index of x-values
# y_column:	column index of y-values (f(x))
#
# Return:	two-dimensional array with an x and an y=f'(x) column
def diff2(nparray, x_column=0, y_column=1):
	if nparray.ndim != 2:
		raise Exception("invalid dimension")
	n = nparray.shape[0] # number of entries (lines)
	c = nparray.shape[1] # number of columns
	if x_column >= c:
		raise Exception("x_column out of index")
	if y_column >= c:
		raise Exception("y_column out of index")
	if n < 2:
		raise Exception("at least two entries are required")

	ret = np.empty(shape=(n - 1, 2), dtype=nparray.dtype)
	for i in range(0, n - 1):
		# x column
		ret[i, 0] = nparray[i + 1, x_column]
		# y comlumn (differentiate)
		ret[i, 1] = (nparray[i + 1, y_column] - nparray[i, y_column]) / (nparray[i + 1, x_column] - nparray[i, x_column])
	return ret


# Return only the entries that mach a specific condition
# s_column:	Column where values are checked for the condition
# cmp_op:       Condition: Comparison operator ("<", "<=", ">", ">=", "==")
# cmp_val:      COndition: Value to which the entry is compared
def subtable_where(nparray, s_column=0, cmp_op=">", cmp_val=0):
	if nparray.ndim != 2:
		raise Exception("invalid dimension")
	n = nparray.shape[0] # number of entries (lines)
	c = nparray.shape[1] # number of columns
	if s_column >= c:
		raise Exception("s_column out of index")
	
	ret = np.empty(shape=(0, c), dtype=nparray.dtype)
	for i in range(0, n):
		cmp = False
		if cmp_op == ">":
			cmp = (nparray[i][s_column] > cmp_val)
		elif cmp_op == ">=":
			cmp = (nparray[i][s_column] >= cmp_val)
		elif cmp_op == "<":
			cmp = (nparray[i][s_column] < cmp_val)
		elif cmp_op == "<=":
			cmp = (nparray[i][s_column] <= cmp_val)
		elif cmp_op == "==":
			cmp = (nparray[i][s_column] == cmp_val)
		if cmp:
			ret = np.append(ret, [nparray[i]], axis=0)
	return ret

# Return only the entries having a maximum value in a specific column
# s_column:	Column where the maximum value is searched
# tolerance:	0.1 = lower upper bound 10% from maximum found value
def subtable_max(nparray, s_column=0, tolerance=0):
	return _subtable_maxmin(nparray, s_column=s_column, tolerance=tolerance, s_opmax=True)

# Return only the entries having a minimum value in a specific column
# s_column:	Column where the maximum value is searched
# tolerance:	0.1 = upper lower bound 10% from minimum found value
def subtable_min(nparray, s_column=0, tolerance=0):
	return _subtable_maxmin(nparray, s_column=s_column, tolerance=tolerance, s_opmax=False)

def _subtable_maxmin(nparray, s_column, tolerance, s_opmax):
        if nparray.ndim != 2:
                raise Exception("invalid dimension")
        n = nparray.shape[0] # number of entries (lines)
        c = nparray.shape[1] # number of columns
        if s_column >= c:
                raise Exception("s_column out of index")

	# Search indices of max/min value
	if s_opmax:
		s_val = np.amax(nparray, axis=0)[s_column]
		s_val -= s_val * tolerance
		return subtable_where(nparray, s_column=s_column, cmp_op=">=", cmp_val=s_val)
	else:
		s_val = np.amin(nparray, axis=0)[s_column]
		s_val += s_val * tolerance
		return subtable_where(nparray, s_column=s_column, cmp_op="<=", cmp_val=s_val)

# Runs a command for a specified period of time
def exec_limited(cmd, time_limit_s):
	print "EXEC(%ds)> %s" % (time_limit_s, ' '.join(cmd))
	p = sp.Popen(cmd)
	time.sleep(time_limit_s)
	p.kill()


# Like 'mktemp': Creates a temporary file and returns its filename
def create_tempfile(prefix="tmp", suffix=""):
	tf = tempfile.NamedTemporaryFile(mode="wr", prefix=prefix, suffix=suffix, delete=False)
	return tf.name


# Return a (almost) unique stamp based on the current time and process id
def get_str_stamp():
	now = datetime.datetime.today()
	return "%04d-%02d-%02d_%02d-%02d-%02d_%05d" % (now.year, now.month, now.day, now.hour, now.minute, now.second, os.getpid())

def str_time(seconds):
	s = seconds
	m = 0
	h = 0
	d = 0

	# days
	while s >= 86400:
		d+=1;
		s-=86400
	# hours
	while s >= 3600:
		h+=1;
		s-=3600
	# minutes
	while s >= 60:
		m+=1;
		s-=60

	if (d > 0):
		return "%d days %02d:%02d:%02d" % (d, h, m , s)
	return "%02d:%02d:%02d" % (h, m , s)

def printf(str, *args):
	sys.stdout.write(str % args)
	sys.stdout.flush()

##
## TEXT BOX, AUTO WRAPPER
## --> add: fig.canvas.mpl_connect('draw_event', mplta_on_draw) before plt.show()
##
# copied from http://stackoverflow.com/questions/4018860/text-box-in-matplotlib
def mplta_on_draw(event):
    """Auto-wraps all text objects in a figure at draw-time"""
    import matplotlib as mpl
    fig = event.canvas.figure

    # Cycle through all artists in all the axes in the figure
    for ax in fig.axes:
        for artist in ax.get_children():
            # If it's a text artist, wrap it...
            if isinstance(artist, mpl.text.Text):
                _mplta_autowrap_text(artist, event.renderer)

    # Temporarily disconnect any callbacks to the draw event...
    # (To avoid recursion)
    func_handles = fig.canvas.callbacks.callbacks[event.name]
    fig.canvas.callbacks.callbacks[event.name] = {}
    # Re-draw the figure..
    fig.canvas.draw()
    # Reset the draw event callbacks
    fig.canvas.callbacks.callbacks[event.name] = func_handles

# copied from http://stackoverflow.com/questions/4018860/text-box-in-matplotlib
def _mplta_autowrap_text(textobj, renderer):
    """Wraps the given matplotlib text object so that it exceed the boundaries
    of the axis it is plotted in."""
    import textwrap
    # Get the starting position of the text in pixels...
    x0, y0 = textobj.get_transform().transform(textobj.get_position())
    # Get the extents of the current axis in pixels...
    clip = textobj.get_axes().get_window_extent()
    # Set the text to rotate about the left edge (doesn't make sense otherwise)
    textobj.set_rotation_mode('anchor')

    # Get the amount of space in the direction of rotation to the left and 
    # right of x0, y0 (left and right are relative to the rotation, as well)
    rotation = textobj.get_rotation()
    right_space = _mplta_min_dist_inside((x0, y0), rotation, clip)
    left_space = _mplta_min_dist_inside((x0, y0), rotation - 180, clip)

    # Use either the left or right distance depending on the horiz alignment.
    alignment = textobj.get_horizontalalignment()
    if alignment is 'left':
        new_width = right_space 
    elif alignment is 'right':
        new_width = left_space
    else:
        new_width = 2 * min(left_space, right_space)

    # Estimate the width of the new size in characters...
    aspect_ratio = 0.5 # This varies with the font!! 
    fontsize = textobj.get_size()
    pixels_per_char = aspect_ratio * renderer.points_to_pixels(fontsize)

    # If wrap_width is < 1, just make it 1 character
    wrap_width = max(1, new_width // pixels_per_char)
    try:
        wrapped_text = textwrap.fill(textobj.get_text(), wrap_width)
    except TypeError:
        # This appears to be a single word
        wrapped_text = textobj.get_text()
    textobj.set_text(wrapped_text)

# copied from http://stackoverflow.com/questions/4018860/text-box-in-matplotlib
def _mplta_min_dist_inside(point, rotation, box):
    """Gets the space in a given direction from "point" to the boundaries of
    "box" (where box is an object with x0, y0, x1, & y1 attributes, point is a
    tuple of x,y, and rotation is the angle in degrees)"""
    from math import sin, cos, radians
    x0, y0 = point
    rotation = radians(rotation)
    distances = []
    threshold = 0.0001 
    if cos(rotation) > threshold: 
        # Intersects the right axis
        distances.append((box.x1 - x0) / cos(rotation))
    if cos(rotation) < -threshold: 
        # Intersects the left axis
        distances.append((box.x0 - x0) / cos(rotation))
    if sin(rotation) > threshold: 
        # Intersects the top axis
        distances.append((box.y1 - y0) / sin(rotation))
    if sin(rotation) < -threshold: 
        # Intersects the bottom axis
        distances.append((box.y0 - y0) / sin(rotation))
    return min(distances)
