#ifndef _LINUX_STEPPER_H_
#define _LINUX_STEPPER_H_

#include <linux/types.h>
#define CONFIG_STEPPER_DEV_MAX		10
#define STEPPER_NAME_SIZE	20

/*states indicate stepper motor direction of rotation*/
enum stepper_direction {
	STEPPER_CLKWISE,
	STEPPER_ANTI_CLKWISE,
	STEPPER_INVALID
};

/*enum options for setting the rate*/
enum stepper_rate_ramp {
	STEPPER_RATE_CONTINUOUS,	/*rate changes immediately complying
						with ramp timer*/
	STEPPER_RATE_DISCONTINUOUS,	/*rate change is effective on
						next start*/
	STEPPER_RATE_INVALID
};

/*options for selecting ramp direction*/
enum stepper_ramp_mode {
	STEPPER_RAMP_UP,
	STEPPER_RAMP_DOWN,
	STEPPER_RAMP_INVALID
};

/*options useful with get_param/set_param API*/
enum stepper_param {
	STEPPER_STATUS,		/*stepper motor driver status. Reads registers
					related to status*/
	STEPPER_START,		/*stepper motor state. value
					1= started, 0= stopped*/
	STEPPER_CW_RATE,	/*clockwise rotation rate.
					Value is a count equivalent to speed.
					value = max pulse width - current pulse width*/
	STEPPER_CCW_RATE,	/*counterclockwise rotation rate.
					Value is a count equivalent to speed.
					value = max pulse width - current pulse width*/
	STEPPER_MAX_RATE,	/*Maximum possible value for rate(CW and CCW)*/
	STEPPER_RAMPUP_VAL,	/*Value represents the rate at which speed
					ramps up*/
	STEPPER_RAMPDOWN_VAL,	/*Value represents the rate at which speed
					ramps down*/
	STEPPER_DIRECTION,	/*parameter to set direction,
					value		0= clockwise,
							1= counter clockwise*/
	STEPPER_CW_STEPS,	/*fixed number of steps to be rotated clockwise
					Maximum value is 0xffff*/
	STEPPER_CCW_STEPS,	/*fixed number of steps to be rotated
					counter clockwise.
					Maximum value is 0xffff*/
	STEPPER_MODE,		 /*0= continuous, 1= reach P0,
					2= CW then CCW, 3=CCW then CW*/
	STEPPER_EMERGENCY,	/*stops the motor immediately on write of
					any value*/
	STEPPER_REG_OP		/*Read or write a register of motor driver*/
};

/*Options for selecting mode of operation*/
enum stepper_mode {
	STEPPER_CONTINUOUS,	/*rotate motor continuously*/
	STEPPER_REACH_P0,	/*rotate motor till P0 sensor senses*/
	STEPPER_CW_THEN_CCW,	/*rotate clockwise for clockwise step count
					and then rotate counterclockwise for
					programmed step count*/
	STEPPER_CCW_THEN_CW,	/*rotate counterclockwise for clockwise
					step count and then rotate clockwise
					for programmed step count*/
	STEPPER_FINITE_STEPS,	/*move fixed number of steps as programmed in
					step count*/
};


/*
	start:	can start the motor.
	restart: used to restart the motor with changed updated parameters
		like speed.
	stop: used to stop the motor
	set_direction: change the direction of rotation as clockwise(0) or
		counter clockwise(1)
	set_rate: set the rate of motor rotation.
	set_ramp_rate: set the rate of incrementing/decrementing motor speed.
	get_param: get parameters specific to the motor driver.
		offset parameter is used to identify register index for
		parameter STEPPER_REG_OP.
	set_param: set parameters specific to motor driver.
		offset parameter is used to
	identify register index for parameter STEPPER_REG_OP.

*/
struct stepper_ops {
	int (*open)(struct device *);
	int (*release)(struct device *);
	int (*ioctl)(struct device *, unsigned int, unsigned long);
	int (*write)(struct device *, const char *, size_t);
	int (*read)(struct device *, char *, size_t);
	int (*start)(struct device *);
	int (*restart)(struct device *);
	int (*stop)(struct device *);
	int (*set_direction)(struct device *, enum stepper_direction);
	int (*set_rate)(struct device *, int, enum stepper_rate_ramp);
	int (*set_ramp_rate)(struct device *, int, enum stepper_ramp_mode);
	int (*get_param)(struct device *, enum stepper_param, loff_t offset);
	int (*set_param)(struct device *, enum stepper_param, loff_t offset,
				int val);
};

/*
structure represents the stepper device.
	dev: device instance created while registering stepper device
	owner: owner of the stepper device
	id: ida assigned id
	offset: used for file operations to seek a specific register
		of the device.
	name: name of the stepper device
	ops: pointer to the stepper device specific function list
	ops_lock: mutex used for all operations on the device.
	chardev: character device registered during registration.
*/
struct stepper_device {
	struct device dev;
	struct module *owner;
	int id;
	loff_t offset;
	char name[STEPPER_NAME_SIZE];
	const struct stepper_ops *ops;
	struct mutex ops_lock;
	struct cdev chardev;
};

/*macro used to get stepper_device pointer using device pointer*/
#define to_stepper_device(dev) container_of(dev, struct stepper_device, dev)

/*function to register a device as stepper driver
@param name - name to be programmed for the device.
@param dev - pointer to the device structure.
@param ops - pointer to the stepper class opertions
@param owner - owner of the device
@ret struct stepper_device * - pointer to stepper_device structure.
*/
extern struct stepper_device *stepper_device_register(const char *name,
		struct device *dev, const struct stepper_ops *ops,
		struct module *owner);

/*stepper class function to get handle of the named device
@param name - name associated with the device during registration
@ret struct stepper_device* - pointer to the stepper device structure.
*/
extern struct stepper_device *stepper_class_open(const char *name);

/*stepper class function to release handle of the named device
@param struct stepper_device* - pointer to the stepper device structure.
*/
extern void stepper_class_close(struct stepper_device *stepper);

/*starts stepper motor with pre-configured parameters like speed,
ramp and mode
@param stepper - pointer to the stepper device structure.
@ret int - status indication for the operation. 0 - successful
*/
extern int stepper_motor_start(struct stepper_device *stepper);

/*when parameters like speed are reconfigured when it is functional,
stepper motor can be restarted with this function to apply
the changes without stopping
@param stepper - pointer to the stepper device structure.
@ret int - status indication for the operation. 0 - successful
*/
extern int stepper_motor_restart(struct stepper_device *stepper);

/*stops the stepper motor by considering ramp down time
@param stepper - pointer to the stepper device structure.
@param is_abrupt - motor can be stopped abruply without complying to
	ramp down sequence. This flag indicates to the driver to
	either stop abruptly(1) or comply with ramp down(0).
@ret int - status indication for the operation. 0 - successful
*/
extern int stepper_motor_stop(struct stepper_device *stepper, bool is_abrupt);

/*sets the direction of rotation as clockwise or counter clockwise
@param stepper - pointer to the stepper device structure.
@param dir - direction in which motor should rotate.	0 - clockwise,
							1 - counter clockwise
@ret int - status indication for the operation. 0 - successful
*/
extern int stepper_motor_direction(struct stepper_device *stepper,
					enum stepper_direction dir);

/*set speed of motor
@param stepper - pointer to the stepper device structure.
@param val - speed value to be set. Value depends on the unit considered
		by device.
e.g, it can be the pulse width for which the driver should hold the coil
		excitation signals.
@param immediate - change in the speed can be effective immediately without
		stopping the motor.
(0) - wait for the motor to stop before considering new speed.
(1) - new speed effective immediately.
@ret int - status indication for the operation. 0 - successful
*/
extern int stepper_motor_setrate(struct stepper_device *stepper, int val,
					enum stepper_rate_ramp immediate);

/*set rate of change of speed
@param stepper - pointer to the stepper device structure.
@param val - value of motor speed. The value can also indicate the width of
		the pulse for energising the coil.
@param immediate - new value set using this function can be immediately
		effective based on this input.
@ret int - status indication for the operation. 0 - successful
*/
extern int stepper_motor_set_ramp(struct stepper_device *stepper, int val,
						enum stepper_ramp_mode dir);

/*remove stepper device
@param stepper - pointer to the stepper device structure.
@ret int - status indication for the operation. 0 - successful
*/
extern void stepper_device_remove(struct stepper_device *stepper);
#endif /*_LINUX_STEPPER_H_*/
