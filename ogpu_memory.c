
int ogpu_init_apertures(struct ogpu_process *process)
{
	uint8_t id = 0;
	struct ogpu_node *dev;
	struct ogpu_process_device *pdd;
	struct pci_dev *pdev = NULL;

	/*Iterating over all devices*/
	for_each_pci_dev(pdev)	
}
